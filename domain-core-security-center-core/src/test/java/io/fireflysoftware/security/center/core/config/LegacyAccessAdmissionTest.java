/*
 * Copyright 2026 Firefly Software Foundation
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy at https://www.apache.org/licenses/LICENSE-2.0
 * Distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND.
 */
package io.fireflysoftware.security.center.core.config;

import io.fireflysoftware.security.center.core.access.SandboxPolicyAccessAdapter;
import io.fireflysoftware.security.center.core.authorization.ReceiverAuthorization;
import io.fireflysoftware.security.center.interfaces.access.AccessAction;
import io.fireflysoftware.security.center.interfaces.access.AccessRequest;
import io.fireflysoftware.security.center.interfaces.access.AccessResourceType;
import io.fireflysoftware.security.center.session.AccessPort;
import io.fireflysoftware.security.center.session.FireflySessionManager;
import io.fireflysoftware.security.center.session.IdentityPort;
import org.fireflyframework.security.api.domain.Decision;
import org.fireflyframework.security.api.domain.SecurityPrincipal;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class LegacyAccessAdmissionTest {
    private static final String ISSUER = "https://identity.example/realms/customers";
    private static final String ACTOR = "11111111-1111-4111-8111-111111111111";

    private SecurityPrincipal principal() {
        return SecurityPrincipal.builder().issuer(ISSUER).subject("opaque-subject").tenantId("opaque-tenant")
                .claims(Map.of("principal_kind", "HUMAN", "client_id", "test-direct-client", "party_id", ACTOR, "tenant_id", "opaque-tenant",
                        "aud", List.of("security-center"), "exp", Instant.now().plusSeconds(300))).build();
    }

    @Test
    void neitherLegacySelectionCanResolveAnIdentityOrSessionWithoutPrincipalOrPolicyPermit() {
        for (String selection : List.of("sandbox", "session-grants")) {
            for (boolean missingPrincipal : new boolean[]{true, false}) {
                IdentityPort identity = mock(IdentityPort.class);
                FireflySessionManager sessions = mock(FireflySessionManager.class);
                AtomicInteger policyCalls = new AtomicInteger();
                var authorization = new ReceiverAuthorization(() -> missingPrincipal ? Mono.empty() : Mono.just(principal()),
                        (p, a, r, c) -> { policyCalls.incrementAndGet(); return Mono.just(Decision.deny("no current permit")); },
                        ISSUER, "security-center", "HUMAN", List.of("test-direct-client"));
                var config = new AccessPortConfiguration();
                AccessPort port = selection.equals("sandbox")
                        ? config.sandboxAccessPort(identity, new DefaultResourceLoader(), SandboxPolicyAccessAdapter.DEFAULT_LOCATION, authorization)
                        : config.sessionGrantAccessPort(identity, sessions, authorization);
                StepVerifier.create(port.decide(AccessRequest.builder().actorId(ACTOR).action(AccessAction.READ)
                                .resourceType(AccessResourceType.ACCOUNT).resourceId("account-one").build()))
                        .expectErrorSatisfies(error -> {
                            assertThat(error).isInstanceOf(ResponseStatusException.class);
                            assertThat(((ResponseStatusException) error).getStatusCode().value()).isEqualTo(missingPrincipal ? 401 : 403);
                        }).verify();
                assertThat(policyCalls).hasValue(missingPrincipal ? 0 : 1);
                verifyNoInteractions(identity, sessions);
            }
        }
    }
    @Test
    void permittedCallerCanStillBeDeniedByEitherAdditionalLegacyRestriction() {
        for (String selection : List.of("sandbox", "session-grants")) {
            IdentityPort identity = mock(IdentityPort.class);
            FireflySessionManager sessions = mock(FireflySessionManager.class);
            AtomicInteger policyCalls = new AtomicInteger();
            when(identity.resolve(ACTOR)).thenAnswer(invocation -> {
                assertThat(policyCalls).hasValue(1);
                return Mono.empty();
            });
            var authorization = new ReceiverAuthorization(() -> Mono.just(principal()),
                    (p, a, r, c) -> { policyCalls.incrementAndGet(); return Mono.just(Decision.permit()); },
                    ISSUER, "security-center", "HUMAN", List.of("test-direct-client"));
            var config = new AccessPortConfiguration();
            AccessPort port = selection.equals("sandbox")
                    ? config.sandboxAccessPort(identity, new DefaultResourceLoader(), SandboxPolicyAccessAdapter.DEFAULT_LOCATION, authorization)
                    : config.sessionGrantAccessPort(identity, sessions, authorization);
            StepVerifier.create(port.decide(AccessRequest.builder().actorId(ACTOR).action(AccessAction.READ)
                            .resourceType(AccessResourceType.ACCOUNT).resourceId("account-one").build()))
                    .assertNext(decision -> assertThat(decision.isAllowed()).isFalse()).verifyComplete();
            verify(identity).resolve(ACTOR);
            verifyNoInteractions(sessions);
        }
    }

}
