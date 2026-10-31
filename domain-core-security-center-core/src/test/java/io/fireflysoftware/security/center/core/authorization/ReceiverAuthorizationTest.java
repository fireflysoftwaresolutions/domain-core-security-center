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

import org.fireflyframework.security.api.domain.Decision;
import org.fireflyframework.security.api.domain.Obligation;
import org.fireflyframework.security.api.domain.SecurityPrincipal;
import org.fireflyframework.security.spi.PolicyDecisionPort;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class ReceiverAuthorizationTest {
    private static final String ISSUER = "https://identity.example/realms/customers";
    private static final String ACTOR = "11111111-1111-4111-8111-111111111111";
    private static final Instant NOW = Instant.parse("2026-10-31T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    private SecurityPrincipal principal(Map<String, Object> replacements) {
        Map<String, Object> claims = new HashMap<>(Map.of("principal_kind", "HUMAN", "client_id", "test-direct-client", "party_id", ACTOR,
                "tenant_id", "opaque/tenant:namespace", "aud", List.of("security-center"), "exp", NOW.plusSeconds(300)));
        claims.putAll(replacements);
        return SecurityPrincipal.builder().issuer(ISSUER).subject("opaque/subject:external")
                .tenantId("opaque/tenant:namespace").claims(claims).build();
    }

    private ReceiverAuthorization guard(Mono<SecurityPrincipal> principal, PolicyDecisionPort policy) {
        return new ReceiverAuthorization(() -> principal, policy, ISSUER, "security-center", "HUMAN", List.of("test-direct-client"), CLOCK);
    }

    private void refused(Mono<?> result, HttpStatus status) {
        StepVerifier.create(result).expectErrorSatisfies(error -> {
            assertThat(error).isInstanceOf(ResponseStatusException.class);
            assertThat(((ResponseStatusException) error).getStatusCode()).isEqualTo(status);
        }).verify();
    }

    @Test
    void missingPrincipalCannotEvaluateCurrentPolicy() {
        AtomicInteger calls = new AtomicInteger();
        ReceiverAuthorization guard = guard(Mono.empty(), (p, a, r, c) -> { calls.incrementAndGet(); return Mono.just(Decision.permit()); });
        refused(guard.authorizeSelf(ACTOR, "READ", "ACCOUNT:one", Map.of()), HttpStatus.UNAUTHORIZED);
        assertThat(calls).hasValue(0);
    }

    @Test
    void currentPolicyReceivesVerifiedOpaqueNamespaceAndExactRequestedOperation() {
        SecurityPrincipal principal = principal(Map.of());
        ReceiverAuthorization guard = guard(Mono.just(principal), (p, action, resource, context) -> {
            assertThat(p).isSameAs(principal);
            assertThat(action).isEqualTo("READ");
            assertThat(resource).isEqualTo("ACCOUNT:one");
            assertThat(context).containsEntry("actorId", ACTOR).containsEntry("tenantId", "opaque/tenant:namespace");
            return Mono.just(Decision.permit());
        });
        StepVerifier.create(guard.authorizeSelf(ACTOR, "READ", "ACCOUNT:one", Map.of()))
                .assertNext(actor -> {
                    assertThat(actor.actorId()).isEqualTo(UUID.fromString(ACTOR));
                    assertThat(actor.principal().subject()).isEqualTo("opaque/subject:external");
                }).verifyComplete();
    }

    @Test
    void wrongActorAndMachineProofNeverReachPolicy() {
        AtomicInteger calls = new AtomicInteger();
        PolicyDecisionPort policy = (p, a, r, c) -> { calls.incrementAndGet(); return Mono.just(Decision.permit()); };
        refused(guard(Mono.just(principal(Map.of())), policy).authorizeSelf(UUID.randomUUID().toString(), "READ", "ACCOUNT:one", Map.of()), HttpStatus.FORBIDDEN);
        refused(guard(Mono.just(principal(Map.of("principal_kind", "MACHINE"))), policy).authorizeSelf(ACTOR, "READ", "ACCOUNT:one", Map.of()), HttpStatus.FORBIDDEN);
        assertThat(calls).hasValue(0);
    }

    @Test
    void missingActorProofExpiredUntypedAndFutureNotBeforeAreRefused() {
        for (Map<String, Object> invalid : List.of(Map.<String, Object>of("party_id", ""),
                Map.<String, Object>of("exp", NOW.minusSeconds(1)), Map.<String, Object>of("exp", NOW.plusSeconds(300).getEpochSecond()),
                Map.<String, Object>of("nbf", NOW.plusSeconds(1)), Map.<String, Object>of("nbf", 1L),
                Map.<String, Object>of("aud", List.of("wrong-service")), Map.<String, Object>of("tenant_id", "another-tenant"))) {
            AtomicInteger calls = new AtomicInteger();
            ReceiverAuthorization guard = guard(Mono.just(principal(invalid)), (p, a, r, c) -> { calls.incrementAndGet(); return Mono.just(Decision.permit()); });
            refused(guard.authorizeSelf(ACTOR, "READ", "ACCOUNT:one", Map.of()), HttpStatus.FORBIDDEN);
            assertThat(calls).hasValue(0);
        }
    }

    @Test
    void wrongIssuerAndCrossPopulationAreRefused() {
        SecurityPrincipal wrongIssuer = principal(Map.of()).toBuilder().issuer("https://untrusted.example").build();
        refused(guard(Mono.just(wrongIssuer), (p, a, r, c) -> Mono.just(Decision.permit())).authorizeSelf(ACTOR, "READ", "ACCOUNT:one", Map.of()), HttpStatus.FORBIDDEN);
        refused(guard(Mono.just(principal(Map.of("principal_kind", "STAFF", "staff_actor_id", ACTOR))), (p, a, r, c) -> Mono.just(Decision.permit())).authorizeSelf(ACTOR, "READ", "ACCOUNT:one", Map.of()), HttpStatus.FORBIDDEN);
    }

    @Test
    void currentPolicyDenyIndeterminateEmptyErrorAndUnfulfilledObligationsAllDeny() {
        for (Mono<Decision> decision : List.of(Mono.just(Decision.deny("denied")), Mono.just(Decision.indeterminate("unknown")),
                Mono.<Decision>empty(), Mono.<Decision>error(new IllegalStateException("private backend detail")),
                Mono.just(Decision.permit(List.of(Obligation.of("mask", Map.of())))))) {
            ReceiverAuthorization guard = guard(Mono.just(principal(Map.of())), (p, a, r, c) -> decision);
            refused(guard.authorizeSelf(ACTOR, "READ", "ACCOUNT:one", Map.of()), HttpStatus.FORBIDDEN);
        }
    }

    @Test
    void absentSignedProofAndSynchronousPolicyFailureCannotAdmitCaller() {
        for (String claim : List.of("party_id", "tenant_id", "exp", "principal_kind")) {
            Map<String, Object> claims = new HashMap<>(principal(Map.of()).claims());
            claims.remove(claim);
            SecurityPrincipal missing = principal(Map.of()).toBuilder().claims(claims).build();
            refused(guard(Mono.just(missing), (p, a, r, c) -> Mono.just(Decision.permit()))
                    .authorizeSelf(ACTOR, "READ", "ACCOUNT:one", Map.of()), HttpStatus.FORBIDDEN);
        }
        refused(guard(Mono.just(principal(Map.of())), (p, a, r, c) -> {
            throw new IllegalStateException("private policy detail");
        }).authorizeSelf(ACTOR, "READ", "ACCOUNT:one", Map.of()), HttpStatus.FORBIDDEN);
    }

    @Test
    void missingWrongUntypedOrWhitespaceClientProofNeverReachesPolicy() {
        for (Object invalid : List.of("", "wrong-client", "test-direct-client ", 17L)) {
            AtomicInteger calls = new AtomicInteger();
            var authorization = guard(Mono.just(principal(Map.of("client_id", invalid))), (p, a, r, c) -> {
                calls.incrementAndGet(); return Mono.just(Decision.permit());
            });
            refused(authorization.authorizeSelf(ACTOR, "READ", "ACCOUNT:one", Map.of()), HttpStatus.FORBIDDEN);
            assertThat(calls).hasValue(0);
        }
        Map<String, Object> claims = new HashMap<>(principal(Map.of()).claims());
        claims.remove("client_id");
        claims.put("azp", "test-direct-client");
        AtomicInteger calls = new AtomicInteger();
        var authorization = guard(Mono.just(principal(Map.of()).toBuilder().claims(claims).build()), (p, a, r, c) -> {
            calls.incrementAndGet(); return Mono.just(Decision.permit());
        });
        refused(authorization.authorizeSelf(ACTOR, "READ", "ACCOUNT:one", Map.of()), HttpStatus.FORBIDDEN);
        assertThat(calls).hasValue(0);
    }

    @Test
    void allowedClientsMustBeExplicitAndVerifiedClientOverwritesCallerContext() {
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> new ReceiverAuthorization(
                () -> Mono.just(principal(Map.of())), (p, a, r, c) -> Mono.just(Decision.permit()),
                ISSUER, "security-center", "HUMAN", null, CLOCK)).isInstanceOf(IllegalArgumentException.class);
        for (List<String> invalid : List.of(List.<String>of(), List.of(""), List.of("client "))) {
            org.assertj.core.api.Assertions.assertThatThrownBy(() -> new ReceiverAuthorization(
                    () -> Mono.just(principal(Map.of())), (p, a, r, c) -> Mono.just(Decision.permit()),
                    ISSUER, "security-center", "HUMAN", invalid, CLOCK)).isInstanceOf(IllegalArgumentException.class);
        }
        var authorization = guard(Mono.just(principal(Map.of())), (p, a, r, c) -> {
            assertThat(c).containsEntry("clientId", "test-direct-client");
            return Mono.just(Decision.permit());
        });
        StepVerifier.create(authorization.authorizeSelf(ACTOR, "READ", "ACCOUNT:one", Map.of("clientId", "forged-client")))
                .expectNextCount(1).verifyComplete();
    }

    @Test
    void signedStaffSelfActorDoesNotBecomeAPartySessionOwner() {
        Map<String, Object> claims = new HashMap<>(principal(Map.of()).claims());
        claims.remove("party_id"); claims.put("principal_kind", "STAFF"); claims.put("staff_actor_id", ACTOR);
        SecurityPrincipal staff = principal(Map.of()).toBuilder().claims(claims).build();
        ReceiverAuthorization guard = new ReceiverAuthorization(() -> Mono.just(staff), (p, a, r, c) -> Mono.just(Decision.permit()),
                ISSUER, "security-center", "STAFF", List.of("test-direct-client"), CLOCK);
        StepVerifier.create(guard.authorizeSelf(ACTOR, "READ", "ACCOUNT:one", Map.of())).expectNextCount(1).verifyComplete();
        refused(guard.authorizeParty(UUID.fromString(ACTOR), "session.read", "session:one", Map.of()), HttpStatus.FORBIDDEN);
    }
}
