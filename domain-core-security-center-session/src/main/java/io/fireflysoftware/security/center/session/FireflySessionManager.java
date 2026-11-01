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

package io.fireflysoftware.security.center.session;

import io.fireflysoftware.security.center.interfaces.dtos.SessionContextDTO;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.UUID;

/**
 * Core session manager interface for the Firefly Core Banking Platform.
 *
 * <p>The FireflySessionManager serves as the central orchestrator for customer session
 * management across all microservices in the platform. It provides a unified interface
 * for creating, retrieving, updating, and invalidating customer sessions while
 * aggregating customer context from multiple domain services.</p>
 *
 * <p><strong>Key Responsibilities:</strong></p>
 * <ul>
 *   <li>Session lifecycle management (create, retrieve, update, invalidate)</li>
 *   <li>Customer context aggregation from multiple microservices</li>
 *   <li>Contract and product relationship management</li>
 *   <li>Role and permission resolution from reference master data</li>
 *   <li>Performance optimization through intelligent caching</li>
 *   <li>Security and audit trail maintenance</li>
 * </ul>
 *
 * <p><strong>Data Flow:</strong></p>
 * <pre>
 * 1. Extract partyId from X-Party-Id header
 * 2. Fetch customer info from customer-mgmt
 * 3. Fetch all active contracts for partyId from contract-mgmt
 * 4. For each contract:
 *    a. Fetch role details from reference-master-data
 *    b. Fetch role scopes (permissions) from reference-master-data
 *    c. Fetch product info from product-mgmt
 * 5. Aggregate into SessionContext
 * 6. Cache and return
 * </pre>
 *
 * <p><strong>Usage Example:</strong></p>
 * <pre>{@code
 * @RestController
 * public class AccountController {
 *
 *     @Autowired
 *     private FireflySessionManager sessionManager;
 *
 *     @GetMapping("/accounts/{productId}")
 *     public Mono<AccountResponse> getAccount(
 *             @PathVariable UUID productId,
 *             ServerWebExchange exchange) {
 *
 *         return sessionManager.createOrGetSession(exchange)
 *             .flatMap(session -> {
 *                 // Validate access to product via contracts
 *                 boolean hasAccess = session.getActiveContracts().stream()
 *                     .anyMatch(c -> c.getProduct().getProductId().equals(productId));
 *
 *                 if (!hasAccess) {
 *                     return Mono.error(new UnauthorizedException());
 *                 }
 *
 *                 return accountService.getAccount(productId, session);
 *             });
 *     }
 * }
 * }</pre>
 *
 * @author Firefly Team
 * @since 1.0.0
 * @see SessionContextDTO
 * @see AccessPort
 */
public interface FireflySessionManager {

    /**
     * Explicitly creates a context when no X-Session-Id is supplied, or retrieves
     * the existing context selected by that header, for the admitted X-Party-Id.
     *
     * <p>This method will:</p>
     * <ol>
     *   <li>Extract partyId from X-Party-Id header</li>
     *   <li>Check cache for existing valid session</li>
     *   <li>Aggregate only for explicit creation without a selected session ID</li>
     *   <li>Cache the session context</li>
     *   <li>Return the complete session</li>
     * </ol>
     *
     * <p>The receiving boundary must authorize the party and supply a verified
     * issuer/tenant namespace. A selected missing, revoked, or expired context
     * is never recreated. Contexts do not authenticate the caller.</p>
     *
     * @param exchange The server web exchange containing headers and request information
     * @return the complete context, or empty for a selected unavailable context
     * @throws IllegalArgumentException if X-Party-Id header is missing or invalid
     */
    Mono<SessionContextDTO> createOrGetSession(ServerWebExchange exchange);

    /**
     * Explicitly creates a new ephemeral context in the current verified namespace.
     * The caller must have independently admitted the party, for example after
     * successful provider authentication. This does not create an identity-provider
     * session or grant business authority. Existing custom implementations fail
     * closed until they implement this separate creation operation.
     */
    default Mono<SessionContextDTO> createSession(UUID partyId) {
        return Mono.error(new UnsupportedOperationException("Explicit session creation is unavailable"));
    }

    /**
     * Retrieves session by party ID.
     *
     * <p>This method only retrieves a previously created live context in the
     * current verified issuer/tenant namespace. A cache miss does not aggregate
     * data or create an authenticated session.</p>
     *
     * @param partyId The party identifier
     * @return the live context, or empty when unavailable
     */
    Mono<SessionContextDTO> getSessionByPartyId(UUID partyId);

    /**
     * Retrieves a previously created live context by opaque session ID in the
     * current verified namespace. Missing or revoked contexts are not recreated.
     *
     * @param sessionId The session identifier
     * @return Mono<SessionContextDTO> containing the session context
     */
    Mono<SessionContextDTO> getSessionBySessionId(String sessionId);

    /**
     * Invalidates a session by session ID.
     *
     * <p>This revokes the cached application context in the current verified
     * namespace. A new explicit creation receives a different identifier.
     * Provider token/session revocation remains a separate operation.</p>
     *
     * @param sessionId The session identifier
     * @return Mono<Void> indicating completion
     */
    Mono<Void> invalidateSession(String sessionId);

    /**
     * Invalidates all contexts for a party in the current verified namespace,
     * without clearing other parties' or tenants' cached contexts.
     *
     * <p>Useful for logout scenarios or when party permissions change.</p>
     *
     * @param partyId The party identifier
     * @return Mono<Void> indicating completion
     */
    Mono<Void> invalidateSessionsByPartyId(UUID partyId);

    /**
     * Refreshes session with updated data from microservices.
     *
     * <p>Only an existing live context is reaggregated. Its identifier, creation
     * time, and original expiration remain unchanged. A missing or revoked
     * context cannot be revived by refresh.</p>
     *
     * @param sessionId The session identifier
     * @return Mono<SessionContextDTO> containing the refreshed session
     */
    Mono<SessionContextDTO> refreshSession(String sessionId);

    /**
     * Validates if session is active and not expired.
     *
     * @param sessionContext The session context to validate
     * @return Mono<Boolean> indicating if session is valid
     */
    Mono<Boolean> isSessionValid(SessionContextDTO sessionContext);

    /**
     * Checks if a party has access to a specific product through any contract.
     *
     * @param partyId The party identifier
     * @param productId The product identifier
     * @return Mono<Boolean> indicating if party has access to the product
     */
    Mono<Boolean> hasAccessToProduct(UUID partyId, UUID productId);

    /**
     * Checks if a party has a specific permission (role scope) for a product.
     *
     * @param partyId The party identifier
     * @param productId The product identifier
     * @param actionType The action type (e.g., READ, WRITE, DELETE)
     * @param resourceType The resource type (e.g., BALANCE, TRANSACTION)
     * @return Mono<Boolean> indicating if party has the permission
     */
    Mono<Boolean> hasPermission(UUID partyId, UUID productId, String actionType, String resourceType);
}
