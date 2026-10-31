/*
 * Copyright 2026 Firefly Software Foundation
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

package io.fireflysoftware.security.center.core.authorization;

import org.fireflyframework.security.api.domain.SecurityPrincipal;
import org.fireflyframework.security.spi.PolicyDecisionPort;
import org.fireflyframework.security.spi.SecurityContextPort;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/** Admits only a verified direct self actor and a current, obligation-free policy permit. */
@Component
public final class ReceiverAuthorization {
    private final SecurityContextPort securityContext;
    private final PolicyDecisionPort policy;
    private final String issuer;
    private final String audience;
    private final String population;
    private final Set<String> allowedClients;
    private final Clock clock;

    @Autowired
    public ReceiverAuthorization(SecurityContextPort securityContext, PolicyDecisionPort policy,
            @Value("${firefly.security-center.receiver.issuer}") String issuer,
            @Value("${firefly.security-center.receiver.audience}") String audience,
            @Value("${firefly.security-center.receiver.population}") String population,
            @Value("${firefly.security-center.receiver.allowed-clients}") List<String> allowedClients) {
        this(securityContext, policy, issuer, audience, population, allowedClients, Clock.systemUTC());
    }

    public ReceiverAuthorization(SecurityContextPort securityContext, PolicyDecisionPort policy,
            String issuer, String audience, String population, List<String> allowedClients, Clock clock) {
        this.securityContext = Objects.requireNonNull(securityContext);
        this.policy = Objects.requireNonNull(policy);
        if (blank(issuer) || blank(audience) || population == null || !Set.of("HUMAN", "STAFF").contains(population)) {
            throw new IllegalArgumentException("Explicit receiver issuer, audience and HUMAN/STAFF population are required");
        }
        if (allowedClients == null || allowedClients.isEmpty() || allowedClients.stream()
                .anyMatch(client -> blank(client) || !client.equals(client.strip()))) {
            throw new IllegalArgumentException("Explicit exact direct-client allowlist is required");
        }
        this.allowedClients = Set.copyOf(allowedClients);
        this.issuer = issuer;
        this.audience = audience;
        this.population = population;
        this.clock = Objects.requireNonNull(clock);
    }

    public Mono<VerifiedActor> authorizeSelf(String requestedActor, String action, String resource, Map<String, Object> context) {
        return authorize(requestedActor, false, action, resource, context);
    }

    public Mono<VerifiedActor> authorizeParty(UUID requestedParty, String action, String resource, Map<String, Object> context) {
        return authorize(requestedParty == null ? null : requestedParty.toString(), true, action, resource, context);
    }

    private Mono<VerifiedActor> authorize(String requestedActor, boolean partyOnly, String action, String resource, Map<String, Object> supplied) {
        return Mono.defer(securityContext::currentPrincipal)
                .switchIfEmpty(Mono.error(new Refusal(HttpStatus.UNAUTHORIZED)))
                .flatMap(principal -> {
                    if (blank(action) || blank(resource)) return Mono.error(new Refusal(HttpStatus.FORBIDDEN));
                    VerifiedActor actor = validate(principal, requestedActor, partyOnly);
                    Map<String, Object> context = new HashMap<>(supplied == null ? Map.of() : supplied);
                    context.put("actorId", actor.actorId().toString());
                    context.put("issuer", principal.issuer());
                    context.put("tenantId", principal.tenantId());
                    context.put("principalKind", population);
                    context.put("clientId", principal.claim("client_id", String.class));
                    return Mono.defer(() -> policy.authorize(principal, action, resource, Map.copyOf(context)))
                            .timeout(Duration.ofSeconds(5))
                            .filter(decision -> decision.granted() && decision.obligations().isEmpty())
                            .switchIfEmpty(Mono.error(new Refusal(HttpStatus.FORBIDDEN)))
                            .map(decision -> {
                                validate(principal, requestedActor, partyOnly);
                                return actor;
                            });
                })
                .onErrorMap(error -> error instanceof Refusal ? error : new Refusal(HttpStatus.FORBIDDEN));
    }

    private VerifiedActor validate(SecurityPrincipal principal, String requestedActor, boolean partyOnly) {
        Instant now = clock.instant();
        Map<String, Object> claims = principal.claims();
        if (!issuer.equals(principal.issuer()) || blank(principal.subject()) || blank(principal.tenantId())
                || !principal.tenantId().equals(claims.get("tenant_id"))
                || !population.equals(claims.get("principal_kind"))
                || !(claims.get("client_id") instanceof String clientId) || clientId.isBlank() || !allowedClients.contains(clientId)
                || partyOnly && !"HUMAN".equals(population)
                || !(claims.get("exp") instanceof Instant expiration) || !expiration.isAfter(now)
                || claims.containsKey("nbf") && (!(claims.get("nbf") instanceof Instant notBefore) || notBefore.isAfter(now))
                || !(claims.get("aud") instanceof Collection<?> audiences) || !audiences.contains(audience)) {
            throw new Refusal(HttpStatus.FORBIDDEN);
        }
        String actorClaim = "HUMAN".equals(population) ? "party_id" : "staff_actor_id";
        String forbiddenClaim = "HUMAN".equals(population) ? "staff_actor_id" : "party_id";
        if (claims.containsKey(forbiddenClaim) || !(claims.get(actorClaim) instanceof String actor)) throw new Refusal(HttpStatus.FORBIDDEN);
        UUID actorId;
        try {
            actorId = UUID.fromString(actor);
            if (!actorId.toString().equals(actor) || requestedActor != null && !actor.equals(requestedActor)) throw new Refusal(HttpStatus.FORBIDDEN);
        } catch (IllegalArgumentException error) { throw new Refusal(HttpStatus.FORBIDDEN); }
        return new VerifiedActor(principal, actorId);
    }

    private static boolean blank(String value) { return value == null || value.isBlank(); }

    public record VerifiedActor(SecurityPrincipal principal, UUID actorId) { }

    private static final class Refusal extends ResponseStatusException {
        private Refusal(HttpStatus status) { super(status, "Verified self actor and current policy admission required"); }
    }
}
