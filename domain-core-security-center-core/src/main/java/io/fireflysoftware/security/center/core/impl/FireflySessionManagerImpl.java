/*
 * Copyright 2025 Firefly Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.fireflysoftware.security.center.core.impl;

import org.fireflyframework.cache.manager.FireflyCacheManager;
import io.fireflysoftware.security.center.core.services.SessionAggregationServiceImpl;
import io.fireflysoftware.security.center.interfaces.dtos.SessionContextDTO;
import io.fireflysoftware.security.center.interfaces.dtos.SessionMetadataDTO;
import io.fireflysoftware.security.center.session.FireflySessionManager;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Implementation of FireflySessionManager with dedicated session cache.
 * <p>
 * Uses the dedicated sessionCacheManager bean created by SessionCacheAutoConfiguration
 * to avoid conflicts with other application caches.
 */
@Service
@Slf4j
public class FireflySessionManagerImpl implements FireflySessionManager {

    private static final String X_PARTY_ID_HEADER = "X-Party-Id";
    private static final String X_SESSION_ID_HEADER = "X-Session-Id";
    private static final String SESSION_CACHE_PREFIX = "session:";
    private static final int DEFAULT_SESSION_TIMEOUT_MINUTES = 30;

    private final SessionAggregationServiceImpl sessionAggregationService;
    private final FireflyCacheManager cacheManager;

    /**
     * Constructor that injects the dedicated session cache manager.
     * 
     * @param sessionAggregationService service for aggregating session data
     * @param cacheManager dedicated session cache manager (qualified bean)
     */
    public FireflySessionManagerImpl(
            SessionAggregationServiceImpl sessionAggregationService,
            @Qualifier("sessionCacheManager") FireflyCacheManager cacheManager) {
        this.sessionAggregationService = sessionAggregationService;
        this.cacheManager = cacheManager;
    }

    @Override
    public Mono<SessionContextDTO> createOrGetSession(ServerWebExchange exchange) {
        String partyIdHeader = exchange.getRequest().getHeaders().getFirst(X_PARTY_ID_HEADER);
        
        if (partyIdHeader == null || partyIdHeader.isBlank()) {
            return Mono.error(new IllegalArgumentException("X-Party-Id header is required"));
        }

        try {
            UUID partyId = UUID.fromString(partyIdHeader);
            String sessionId = extractOrGenerateSessionId(exchange, partyId);

            log.debug("Creating or retrieving session for partyId: {}, sessionId: {}", partyId, sessionId);

            return getOrCreateSession(sessionId, partyId, exchange);
        } catch (IllegalArgumentException e) {
            return Mono.error(new IllegalArgumentException("Invalid X-Party-Id format", e));
        }
    }

    @Override
    public Mono<SessionContextDTO> getSessionByPartyId(UUID partyId) {
        log.debug("Retrieving session by partyId: {}", partyId);
        String sessionId = generateSessionId(partyId);
        return getOrCreateSessionInternal(sessionId, partyId, null, null, null);
    }

    @Override
    public Mono<SessionContextDTO> getSessionBySessionId(String sessionId) {
        log.debug("Retrieving session by sessionId: {}", sessionId);

        String cacheKey = SESSION_CACHE_PREFIX + sessionId;

        return cacheManager.get(cacheKey, SessionContextDTO.class)
            .flatMap(cached -> {
                if (cached.isPresent()) {
                    log.debug("Session found in cache: {}", sessionId);
                    return Mono.just(cached.get());
                }

                log.debug("Session not in cache, creating new session: {}", sessionId);
                UUID partyId = extractPartyIdFromSessionId(sessionId);
                return getOrCreateSessionInternal(sessionId, partyId, null, null, null)
                    .flatMap(session -> cacheManager.put(cacheKey, session,
                            Duration.ofMinutes(DEFAULT_SESSION_TIMEOUT_MINUTES))
                        .thenReturn(session));
            });
    }

    @Override
    public Mono<Void> invalidateSession(String sessionId) {
        log.info("Invalidating session: {}", sessionId);
        String cacheKey = SESSION_CACHE_PREFIX + sessionId;
        return cacheManager.evict(cacheKey).then();
    }

    @Override
    public Mono<Void> invalidateSessionsByPartyId(UUID partyId) {
        log.info("Invalidating all sessions for partyId: {}", partyId);
        // Clear all caches - FireflyCacheManager will handle the eviction
        return cacheManager.clear();
    }

    @Override
    public Mono<SessionContextDTO> refreshSession(String sessionId) {
        log.info("Refreshing session: {}", sessionId);
        String cacheKey = SESSION_CACHE_PREFIX + sessionId;
        UUID partyId = extractPartyIdFromSessionId(sessionId);
        
        return cacheManager.evict(cacheKey)
            .then(getOrCreateSessionInternal(sessionId, partyId, null, null, null));
    }

    @Override
    public Mono<Boolean> isSessionValid(SessionContextDTO sessionContext) {
        if (sessionContext == null) {
            return Mono.just(false);
        }

        LocalDateTime now = LocalDateTime.now();
        boolean isNotExpired = sessionContext.getExpiresAt() != null && 
                               sessionContext.getExpiresAt().isAfter(now);
        boolean isActive = SessionContextDTO.SessionStatus.ACTIVE.equals(sessionContext.getStatus());

        return Mono.just(isNotExpired && isActive);
    }

    @Override
    public Mono<Boolean> hasAccessToProduct(UUID partyId, UUID productId) {
        log.debug("Checking access for partyId: {} to productId: {}", partyId, productId);
        
        return getSessionByPartyId(partyId)
            .map(session -> session.getActiveContracts().stream()
                .anyMatch(contract -> contract.getProduct() != null &&
                                     productId.equals(contract.getProduct().getProductId()) &&
                                     Boolean.TRUE.equals(contract.getIsActive())))
            .defaultIfEmpty(false);
    }

    @Override
    public Mono<Boolean> hasPermission(UUID partyId, UUID productId, String actionType, String resourceType) {
        log.debug("Checking permission for partyId: {} on productId: {} - action: {}, resource: {}",
                partyId, productId, actionType, resourceType);

        return getSessionByPartyId(partyId)
            .map(session -> session.getActiveContracts().stream()
                .filter(contract -> contract.getProduct() != null &&
                                   productId.equals(contract.getProduct().getProductId()) &&
                                   Boolean.TRUE.equals(contract.getIsActive()))
                .flatMap(contract -> contract.getRoleInContract().getScopes().stream())
                .anyMatch(scope -> actionType.equalsIgnoreCase(scope.getActionType()) &&
                                  (resourceType == null || resourceType.equalsIgnoreCase(scope.getResourceType())) &&
                                  Boolean.TRUE.equals(scope.getIsActive())))
            .defaultIfEmpty(false);
    }

    private Mono<SessionContextDTO> getOrCreateSession(String sessionId, UUID partyId, ServerWebExchange exchange) {
        String cacheKey = SESSION_CACHE_PREFIX + sessionId;
        
        return cacheManager.get(cacheKey, SessionContextDTO.class)
            .flatMap(cached -> {
                if (cached.isPresent()) {
                    log.debug("Session found in cache: {}", sessionId);
                    // Update last accessed time
                    SessionContextDTO updated = cached.get().toBuilder()
                        .lastAccessedAt(LocalDateTime.now())
                        .build();
                    return cacheManager.put(cacheKey, updated,
                            Duration.ofMinutes(DEFAULT_SESSION_TIMEOUT_MINUTES))
                        .thenReturn(updated);
                }
                
                log.debug("Session not in cache, creating new: {}", sessionId);
                String ipAddress = getClientIpAddress(exchange);
                String userAgent = getUserAgent(exchange);
                SessionMetadataDTO metadata = buildSessionMetadata(exchange);
                
                return getOrCreateSessionInternal(sessionId, partyId, ipAddress, userAgent, metadata)
                    .flatMap(session -> cacheManager.put(cacheKey, session,
                            Duration.ofMinutes(DEFAULT_SESSION_TIMEOUT_MINUTES))
                        .thenReturn(session));
            });
    }

    private Mono<SessionContextDTO> getOrCreateSessionInternal(
            String sessionId, 
            UUID partyId, 
            String ipAddress, 
            String userAgent, 
            SessionMetadataDTO metadata) {

        log.info("Creating new session for partyId: {}", partyId);

        return sessionAggregationService.aggregateSessionContext(partyId)
            .map(aggregatedSession -> {
                LocalDateTime now = LocalDateTime.now();
                
                return aggregatedSession.toBuilder()
                    .sessionId(sessionId)
                    .partyId(partyId)
                    .createdAt(now)
                    .lastAccessedAt(now)
                    .expiresAt(now.plusMinutes(DEFAULT_SESSION_TIMEOUT_MINUTES))
                    .ipAddress(ipAddress)
                    .userAgent(userAgent)
                    .status(SessionContextDTO.SessionStatus.ACTIVE)
                    .metadata(metadata)
                    .build();
            });
    }

    private String extractOrGenerateSessionId(ServerWebExchange exchange, UUID partyId) {
        String sessionIdHeader = exchange.getRequest().getHeaders().getFirst(X_SESSION_ID_HEADER);
        return (sessionIdHeader != null && !sessionIdHeader.isBlank()) 
            ? sessionIdHeader 
            : generateSessionId(partyId);
    }

    private String generateSessionId(UUID partyId) {
        return "session_" + partyId.toString() + "_" + System.currentTimeMillis();
    }

    private UUID extractPartyIdFromSessionId(String sessionId) {
        try {
            String[] parts = sessionId.split("_");
            if (parts.length >= 2) {
                return UUID.fromString(parts[1]);
            }
        } catch (Exception e) {
            log.warn("Failed to extract partyId from sessionId: {}", sessionId, e);
        }
        throw new IllegalArgumentException("Invalid session ID format");
    }

    private String getClientIpAddress(ServerWebExchange exchange) {
        String xForwardedFor = exchange.getRequest().getHeaders().getFirst("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIp = exchange.getRequest().getHeaders().getFirst("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }

        return exchange.getRequest().getRemoteAddress() != null
            ? exchange.getRequest().getRemoteAddress().getAddress().getHostAddress()
            : "unknown";
    }

    private String getUserAgent(ServerWebExchange exchange) {
        return exchange.getRequest().getHeaders().getFirst("User-Agent");
    }

    private SessionMetadataDTO buildSessionMetadata(ServerWebExchange exchange) {
        return SessionMetadataDTO.builder()
            .channel(determineChannel(exchange))
            .sourceApplication(exchange.getRequest().getHeaders().getFirst("X-Source-Application"))
            .deviceInfo(getUserAgent(exchange))
            .build();
    }

    private String determineChannel(ServerWebExchange exchange) {
        String userAgent = getUserAgent(exchange);
        if (userAgent != null) {
            if (userAgent.contains("Mobile")) {
                return "mobile";
            } else if (userAgent.contains("Mozilla")) {
                return "web";
            }
        }
        return "api";
    }
}
