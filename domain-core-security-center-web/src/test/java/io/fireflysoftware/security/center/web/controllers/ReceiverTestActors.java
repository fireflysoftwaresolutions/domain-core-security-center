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

package io.fireflysoftware.security.center.web.controllers;

import io.fireflysoftware.security.center.core.authorization.ReceiverAuthorization;
import org.fireflyframework.security.api.domain.Decision;
import org.fireflyframework.security.api.domain.SecurityPrincipal;
import org.fireflyframework.security.spi.PolicyDecisionPort;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class ReceiverTestActors {
    static final String ACTOR = "11111111-1111-4111-8111-111111111111";
    static final String ISSUER = "https://identity.example/realms/customers";

    static SecurityPrincipal human() {
        return SecurityPrincipal.builder().issuer(ISSUER).subject("opaque/human:one").tenantId("opaque-tenant")
                .authorities(Set.of("signed-profile-reader"))
                .claims(Map.of("principal_kind", "HUMAN", "client_id", "test-direct-client", "party_id", ACTOR, "tenant_id", "opaque-tenant",
                        "aud", List.of("security-center"), "exp", Instant.now().plusSeconds(300))).build();
    }

    static ReceiverAuthorization guard(Mono<SecurityPrincipal> principal, PolicyDecisionPort policy) {
        return new ReceiverAuthorization(() -> principal, policy, ISSUER, "security-center", "HUMAN", List.of("test-direct-client"));
    }

    static ReceiverAuthorization permitted() {
        return guard(Mono.just(human()), (p, a, r, c) -> Mono.just(Decision.permit()));
    }
}
