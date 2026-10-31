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

import io.fireflysoftware.security.center.core.services.SessionAggregationService;
import io.fireflysoftware.security.center.interfaces.dtos.ContractInfoDTO;
import io.fireflysoftware.security.center.interfaces.dtos.SessionContextDTO;
import io.fireflysoftware.security.center.interfaces.dtos.SessionMetadataDTO;
import io.fireflysoftware.security.center.session.FireflySessionManager;
import org.fireflyframework.cache.manager.FireflyCacheManager;
import org.fireflyframework.security.spi.SecurityContextPort;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Function;

/** Ephemeral application contexts; provider authentication and business data remain separate. */
@Service
public class FireflySessionManagerImpl implements FireflySessionManager {

    private static final Duration SESSION_TTL = Duration.ofMinutes(30);
    private static final Duration GENERATION_TTL = Duration.ofHours(1);
    private final SessionAggregationService sessionAggregationService;
    private final FireflyCacheManager cacheManager;
    private final SecurityContextPort contexts;
    private final Clock clock;

    @Autowired
    public FireflySessionManagerImpl(SessionAggregationService sessionAggregationService,
            @Qualifier("sessionCacheManager") FireflyCacheManager cacheManager, SecurityContextPort contexts) {
        this(sessionAggregationService, cacheManager, contexts, Clock.systemUTC());
    }

    /** Preserves constructor linkage without introducing an unscoped trusted mode. */
    public FireflySessionManagerImpl(SessionAggregationService sessionAggregationService, FireflyCacheManager cacheManager) {
        this(sessionAggregationService, cacheManager, Mono::empty, Clock.systemUTC());
    }

    FireflySessionManagerImpl(SessionAggregationService sessionAggregationService, FireflyCacheManager cacheManager,
            SecurityContextPort contexts, Clock clock) {
        this.sessionAggregationService = Objects.requireNonNull(sessionAggregationService);
        this.cacheManager = Objects.requireNonNull(cacheManager);
        this.contexts = Objects.requireNonNull(contexts);
        this.clock = Objects.requireNonNull(clock);
    }

    @Override
    public Mono<SessionContextDTO> createOrGetSession(ServerWebExchange exchange) {
        return withScope(scope -> {
            UUID party = canonicalUuid(header(exchange, "X-Party-Id", true));
            String selected = header(exchange, "X-Session-Id", false);
            if (selected == null) {
                return create(scope, party, exchange);
            }
            if (!party.equals(partyFromId(selected))) {
                return Mono.error(new IllegalArgumentException("Session party does not match"));
            }
            return lookup(scope, selected).map(value -> copy(value.session()));
        });
    }

    @Override
    public Mono<SessionContextDTO> createSession(UUID partyId) {
        return withScope(scope -> create(scope, partyId, null));
    }

    @Override
    public Mono<SessionContextDTO> getSessionByPartyId(UUID partyId) {
        return withScope(scope -> generation(scope, partyId, false).flatMap(generation ->
                cacheManager.get(currentKey(scope, partyId, generation), String.class)
                        .flatMap(value -> Mono.justOrEmpty(value))
                        .flatMap(id -> {
                            if (!partyId.equals(partyFromId(id))) return Mono.error(stateChanged());
                            return lookup(scope, id).map(value -> copy(value.session()));
                        })));
    }

    @Override
    public Mono<SessionContextDTO> getSessionBySessionId(String sessionId) {
        return withScope(scope -> lookup(scope, sessionId).map(value -> copy(value.session())));
    }

    @Override
    public Mono<Void> invalidateSession(String sessionId) {
        return withScope(scope -> {
            UUID party = partyFromId(sessionId);
            // Refresh never writes this permit, so an in-flight refresh cannot undo revocation.
            return requireScope(scope).then(cacheManager.evict(liveKey(scope, party, sessionId)))
                    .filter(Boolean::booleanValue).switchIfEmpty(Mono.error(stateChanged()))
                    .then(cacheManager.get(liveKey(scope, party, sessionId), String.class))
                    .filter(java.util.Optional::isEmpty).switchIfEmpty(Mono.error(stateChanged())).then();
        });
    }

    @Override
    public Mono<Void> invalidateSessionsByPartyId(UUID partyId) {
        return withScope(scope -> {
            requireParty(partyId);
            var next = new CachedGeneration(UUID.randomUUID().toString(), clock.instant().plus(GENERATION_TTL));
            // Rotation makes every older generation inaccessible, including writes already in flight.
            return requireScope(scope).then(cacheManager.put(generationKey(scope, partyId), next, GENERATION_TTL))
                    .then(cacheManager.get(generationKey(scope, partyId), CachedGeneration.class))
                    .filter(value -> value.filter(next::equals).isPresent())
                    .switchIfEmpty(Mono.error(stateChanged())).then();
        });
    }

    @Override
    public Mono<SessionContextDTO> refreshSession(String sessionId) {
        return withScope(scope -> lookup(scope, sessionId).flatMap(original -> {
            UUID party = original.partyId();
            return generation(scope, party, false).flatMap(generation -> {
                if (!generation.id().equals(original.generation())) return Mono.error(stateChanged());
                return aggregate(party).flatMap(aggregated -> {
                    var previous = original.session();
                    var refreshed = aggregated.toBuilder().sessionId(sessionId).partyId(party)
                            .createdAt(previous.getCreatedAt()).lastAccessedAt(now())
                            .expiresAt(previous.getExpiresAt()).status(SessionContextDTO.SessionStatus.ACTIVE)
                            .ipAddress(previous.getIpAddress()).userAgent(previous.getUserAgent())
                            .metadata(previous.getMetadata()).build();
                    var replacement = new CachedSession(scope.issuer(), scope.tenant(), party, generation.id(), original.livePermit(), refreshed);
                    return fence(scope, party, generation, sessionId, original.livePermit())
                            .then(cacheManager.put(entryKey(scope, party, generation, sessionId), replacement, ttl(refreshed)))
                            .then(verifyStored(scope, party, generation, sessionId, replacement))
                            .thenReturn(copy(refreshed));
                });
            });
        }));
    }

    @Override
    public Mono<Boolean> isSessionValid(SessionContextDTO sessionContext) {
        if (sessionContext == null || !active(sessionContext)) return Mono.just(false);
        return getSessionBySessionId(sessionContext.getSessionId()).map(stored ->
                Objects.equals(stored.getPartyId(), sessionContext.getPartyId())
                        && Objects.equals(stored.getCreatedAt(), sessionContext.getCreatedAt())
                        && Objects.equals(stored.getExpiresAt(), sessionContext.getExpiresAt())).defaultIfEmpty(false);
    }

    @Override
    public Mono<Boolean> hasAccessToProduct(UUID partyId, UUID productId) {
        return getSessionByPartyId(partyId).map(session -> contracts(session).stream().anyMatch(contract ->
                contract != null && contract.getProduct() != null
                        && productId != null && productId.equals(contract.getProduct().getProductId())
                        && Boolean.TRUE.equals(contract.getIsActive()))).defaultIfEmpty(false);
    }

    @Override
    public Mono<Boolean> hasPermission(UUID partyId, UUID productId, String actionType, String resourceType) {
        return getSessionByPartyId(partyId).map(session -> contracts(session).stream()
                .filter(contract -> contract != null && contract.getProduct() != null
                        && productId != null && productId.equals(contract.getProduct().getProductId())
                        && Boolean.TRUE.equals(contract.getIsActive()) && contract.getRoleInContract() != null
                        && contract.getRoleInContract().getScopes() != null)
                .flatMap(contract -> contract.getRoleInContract().getScopes().stream())
                .anyMatch(scope -> scope != null && actionType != null && actionType.equalsIgnoreCase(scope.getActionType())
                        && (resourceType == null || resourceType.equalsIgnoreCase(scope.getResourceType()))
                        && Boolean.TRUE.equals(scope.getIsActive()))).defaultIfEmpty(false);
    }

    private Mono<SessionContextDTO> create(Scope scope, UUID party, ServerWebExchange exchange) {
        requireParty(party);
        return generation(scope, party, true).flatMap(generation -> {
            String id = "session_" + party + "_" + UUID.randomUUID();
            String livePermit = UUID.randomUUID().toString();
            Instant started = clock.instant();
            return aggregate(party).flatMap(aggregated -> {
                Instant expires = minimum(started.plus(SESSION_TTL), generation.expiresAt(), scope.expiresAt());
                var session = aggregated.toBuilder().sessionId(id).partyId(party)
                        .createdAt(LocalDateTime.ofInstant(started, ZoneOffset.UTC)).lastAccessedAt(now())
                        .expiresAt(LocalDateTime.ofInstant(expires, ZoneOffset.UTC))
                        .status(SessionContextDTO.SessionStatus.ACTIVE)
                        .ipAddress(exchange == null ? null : clientIp(exchange))
                        .userAgent(exchange == null ? null : exchange.getRequest().getHeaders().getFirst("User-Agent"))
                        .metadata(exchange == null ? null : metadata(exchange)).build();
                var entry = new CachedSession(scope.issuer(), scope.tenant(), party, generation.id(), livePermit, session);
                return fenceGeneration(scope, party, generation)
                        .then(cacheManager.putIfAbsent(liveKey(scope, party, id), livePermit, ttl(session)))
                        .filter(Boolean::booleanValue).switchIfEmpty(Mono.error(stateChanged()))
                        .then(fence(scope, party, generation, id, livePermit))
                        .then(cacheManager.putIfAbsent(entryKey(scope, party, generation, id), entry, ttl(session)))
                        .filter(Boolean::booleanValue).switchIfEmpty(Mono.error(stateChanged()))
                        .then(verifyStored(scope, party, generation, id, entry))
                        .then(cacheManager.put(currentKey(scope, party, generation), id, ttl(session)))
                        .then(cacheManager.get(currentKey(scope, party, generation), String.class))
                        .flatMap(value -> Mono.justOrEmpty(value))
                        .flatMap(current -> {
                            if (!party.equals(partyFromId(current))) return Mono.error(stateChanged());
                            return lookup(scope, current);
                        })
                        .switchIfEmpty(Mono.error(stateChanged()))
                        .then(fence(scope, party, generation, id, livePermit)).thenReturn(copy(session));
            });
        });
    }

    private Mono<SessionContextDTO> aggregate(UUID party) {
        return Mono.defer(() -> sessionAggregationService.aggregateSessionContext(party))
                .filter(session -> party.equals(session.getPartyId()))
                .switchIfEmpty(Mono.error(stateChanged()));
    }

    private Mono<CachedSession> lookup(Scope scope, String id) {
        UUID party = partyFromId(id);
        return generation(scope, party, false).flatMap(generation ->
                cacheManager.get(liveKey(scope, party, id), String.class)
                        .flatMap(value -> Mono.justOrEmpty(value))
                        .flatMap(permit -> cacheManager.get(entryKey(scope, party, generation, id), CachedSession.class)
                                        .flatMap(value -> Mono.justOrEmpty(value))
                                        .flatMap(entry -> {
                                            validate(entry, scope, party, generation, id);
                                            if (!permit.equals(entry.livePermit())) return Mono.error(stateChanged());
                                            if (!active(entry.session())) return Mono.empty();
                                            return fence(scope, party, generation, id, permit).thenReturn(entry);
                                        })));
    }

    private Mono<Void> verifyStored(Scope scope, UUID party, CachedGeneration generation, String id, CachedSession expected) {
        return cacheManager.get(entryKey(scope, party, generation, id), CachedSession.class)
                .filter(value -> value.filter(expected::equals).isPresent())
                .doOnNext(value -> {
                    validate(expected, scope, party, generation, id);
                    if (!active(expected.session())) throw stateChanged();
                })
                .switchIfEmpty(Mono.error(stateChanged())).then(fence(scope, party, generation, id, expected.livePermit()));
    }

    private Mono<CachedGeneration> generation(Scope scope, UUID party, boolean create) {
        requireParty(party);
        var read = Mono.defer(() -> cacheManager.get(generationKey(scope, party), CachedGeneration.class))
                .flatMap(value -> Mono.justOrEmpty(value)).map(value -> {
                    canonicalUuid(value.id());
                    if (value.expiresAt() == null || !clock.instant().isBefore(value.expiresAt())
                            || value.expiresAt().isAfter(clock.instant().plus(GENERATION_TTL))) throw stateChanged();
                    return value;
                });
        if (!create) return read;
        return read.switchIfEmpty(Mono.defer(() -> {
            var candidate = new CachedGeneration(UUID.randomUUID().toString(), clock.instant().plus(GENERATION_TTL));
            return cacheManager.putIfAbsent(generationKey(scope, party), candidate, GENERATION_TTL)
                    .then(read).switchIfEmpty(Mono.error(stateChanged()));
        }));
    }

    private Mono<Void> fenceGeneration(Scope scope, UUID party, CachedGeneration generation) {
        return requireScope(scope).then(generation(scope, party, false))
                .filter(generation::equals).switchIfEmpty(Mono.error(stateChanged())).then();
    }

    private Mono<Void> fence(Scope scope, UUID party, CachedGeneration generation, String id, String permit) {
        return fenceGeneration(scope, party, generation)
                .then(cacheManager.get(liveKey(scope, party, id), String.class))
                .filter(value -> value.filter(permit::equals).isPresent())
                .switchIfEmpty(Mono.error(stateChanged())).then();
    }

    private void validate(CachedSession entry, Scope scope, UUID party, CachedGeneration generation, String id) {
        var session = entry.session();
        if (!scope.issuer().equals(entry.issuer()) || !scope.tenant().equals(entry.platformTenant())
                || !party.equals(entry.partyId()) || !generation.id().equals(entry.generation()) || session == null
                || !id.equals(session.getSessionId()) || !party.equals(session.getPartyId())
                || session.getCreatedAt() == null || session.getExpiresAt() == null
                || session.getCreatedAt().isAfter(now())
                || session.getExpiresAt().isAfter(session.getCreatedAt().plus(SESSION_TTL))
                || session.getExpiresAt().isAfter(LocalDateTime.ofInstant(generation.expiresAt(), ZoneOffset.UTC))) {
            throw stateChanged();
        }
    }

    private <T> Mono<T> withScope(Function<Scope, Mono<T>> work) {
        return Mono.defer(() -> currentScope().flatMap(work));
    }

    private Mono<Scope> currentScope() {
        return Mono.defer(contexts::currentPrincipal).switchIfEmpty(Mono.error(stateChanged())).map(principal -> {
            String issuer = text(principal.issuer(), 500), tenant = text(principal.tenantId(), 1024);
            String subject = text(principal.subject(), 255);
            Instant expires = principal.claim("exp", Instant.class);
            if (expires == null || !clock.instant().isBefore(expires)) throw stateChanged();
            return new Scope(issuer, tenant, subject, expires);
        });
    }

    private Mono<Void> requireScope(Scope expected) {
        return currentScope().filter(expected::equals).switchIfEmpty(Mono.error(stateChanged())).then();
    }

    private boolean active(SessionContextDTO session) {
        return session != null && session.getStatus() == SessionContextDTO.SessionStatus.ACTIVE
                && session.getExpiresAt() != null && now().isBefore(session.getExpiresAt());
    }

    private Duration ttl(SessionContextDTO session) {
        Duration remaining = Duration.between(now(), session.getExpiresAt());
        if (remaining.isNegative() || remaining.isZero() || remaining.compareTo(SESSION_TTL) > 0) throw stateChanged();
        return remaining;
    }

    private LocalDateTime now() { return LocalDateTime.now(clock); }
    private static SessionContextDTO copy(SessionContextDTO session) { return session.toBuilder().build(); }
    private static List<ContractInfoDTO> contracts(SessionContextDTO session) {
        return session.getActiveContracts() == null ? List.of() : session.getActiveContracts();
    }
    private static Instant minimum(Instant first, Instant second, Instant third) {
        return first.isBefore(second) ? (first.isBefore(third) ? first : third) : (second.isBefore(third) ? second : third);
    }
    private static String prefix(Scope scope, UUID party) {
        var encoder = Base64.getUrlEncoder().withoutPadding();
        return "session:v2:" + encoder.encodeToString(scope.issuer().getBytes(StandardCharsets.UTF_8)) + ":"
                + encoder.encodeToString(scope.tenant().getBytes(StandardCharsets.UTF_8)) + ":" + party + ":";
    }
    private static String generationKey(Scope scope, UUID party) { return prefix(scope, party) + "generation"; }
    private static String currentKey(Scope scope, UUID party, CachedGeneration generation) {
        return prefix(scope, party) + "current:" + generation.id();
    }
    private static String entryKey(Scope scope, UUID party, CachedGeneration generation, String id) {
        return prefix(scope, party) + "entry:" + generation.id() + ":" + id;
    }
    private static String liveKey(Scope scope, UUID party, String id) { return prefix(scope, party) + "live:" + id; }
    private static String header(ServerWebExchange exchange, String name, boolean required) {
        if (exchange == null) throw new IllegalArgumentException("Session request is required");
        var values = exchange.getRequest().getHeaders().get(name);
        if (values == null && !required) return null;
        if (values == null || values.size() != 1 || values.getFirst() == null || values.getFirst().isBlank())
            throw new IllegalArgumentException("One session header value is required");
        return values.getFirst();
    }
    private static UUID partyFromId(String id) {
        if (id == null || id.length() > 100) throw new IllegalArgumentException("Invalid session identifier");
        String[] parts = id.split("_", -1);
        if (parts.length != 3 || !"session".equals(parts[0])) throw new IllegalArgumentException("Invalid session identifier");
        canonicalUuid(parts[2]);
        return canonicalUuid(parts[1]);
    }
    private static UUID canonicalUuid(String value) {
        if (value == null || value.length() != 36) throw new IllegalArgumentException("Canonical identifier required");
        UUID id = UUID.fromString(value);
        if (!id.toString().equals(value) || id.equals(new UUID(0, 0))) throw new IllegalArgumentException("Canonical identifier required");
        return id;
    }
    private static void requireParty(UUID party) {
        if (party == null || party.equals(new UUID(0, 0))) throw new IllegalArgumentException("Party is required");
    }
    private static String text(String value, int maximumBytes) {
        if (value == null || value.isBlank() || value.getBytes(StandardCharsets.UTF_8).length > maximumBytes
                || value.codePoints().anyMatch(c -> Character.isISOControl(c) || c >= 0xd800 && c <= 0xdfff)) throw stateChanged();
        return value;
    }
    private static String clientIp(ServerWebExchange exchange) {
        String forwarded = exchange.getRequest().getHeaders().getFirst("X-Forwarded-For");
        if (forwarded != null && !forwarded.isEmpty()) return forwarded.split(",")[0].trim();
        String real = exchange.getRequest().getHeaders().getFirst("X-Real-IP");
        if (real != null && !real.isEmpty()) return real;
        return exchange.getRequest().getRemoteAddress() == null ? "unknown"
                : exchange.getRequest().getRemoteAddress().getAddress().getHostAddress();
    }
    private static SessionMetadataDTO metadata(ServerWebExchange exchange) {
        String agent = exchange.getRequest().getHeaders().getFirst("User-Agent");
        String channel = agent != null && agent.contains("Mobile") ? "mobile"
                : agent != null && agent.contains("Mozilla") ? "web" : "api";
        return SessionMetadataDTO.builder().channel(channel).deviceInfo(agent)
                .sourceApplication(exchange.getRequest().getHeaders().getFirst("X-Source-Application")).build();
    }
    private static IllegalStateException stateChanged() { return new IllegalStateException("Verified session state is unavailable"); }
    private record Scope(String issuer, String tenant, String subject, Instant expiresAt) {}
    public record CachedGeneration(String id, Instant expiresAt) {}
    public record CachedSession(String issuer, String platformTenant, UUID partyId, String generation, String livePermit, SessionContextDTO session) {}
}
