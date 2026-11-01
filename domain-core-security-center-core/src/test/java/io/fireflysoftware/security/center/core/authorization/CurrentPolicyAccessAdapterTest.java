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

import io.fireflysoftware.security.center.interfaces.access.AccessAction;
import io.fireflysoftware.security.center.interfaces.access.AccessDecision;
import io.fireflysoftware.security.center.interfaces.access.AccessRequest;
import io.fireflysoftware.security.center.interfaces.access.AccessResourceType;
import org.fireflyframework.security.api.domain.Decision;
import org.fireflyframework.security.api.domain.SecurityPrincipal;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class CurrentPolicyAccessAdapterTest {
    @Test
    void internalAccessPortUsesVerifiedCallerAndExactCurrentPolicyWithoutTargetIdentityLookup() {
        String issuer = "https://identity.example/realms/customers";
        String actor = "11111111-1111-4111-8111-111111111111";
        SecurityPrincipal principal = SecurityPrincipal.builder().issuer(issuer).subject("opaque-subject")
                .tenantId("opaque-tenant").claims(Map.of("principal_kind", "HUMAN", "client_id", "test-direct-client", "party_id", actor,
                        "tenant_id", "opaque-tenant", "aud", List.of("security-center"), "exp", Instant.now().plusSeconds(300))).build();
        ReceiverAuthorization authorization = new ReceiverAuthorization(() -> Mono.just(principal), (p, a, r, c) -> {
            assertThat(p).isSameAs(principal);
            assertThat(a).isEqualTo("READ");
            assertThat(r).isEqualTo("ACCOUNT:account-one");
            return Mono.just(Decision.permit());
        }, issuer, "security-center", "HUMAN", List.of("test-direct-client"));
        var adapter = new CurrentPolicyAccessAdapter(authorization);
        StepVerifier.create(adapter.decide(AccessRequest.builder().actorId(actor).action(AccessAction.READ)
                        .resourceType(AccessResourceType.ACCOUNT).resourceId("account-one").build()))
                .assertNext(decision -> {
                    assertThat(decision.isAllowed()).isTrue();
                    assertThat(decision.getReasonCode()).isEqualTo(AccessDecision.CURRENT_POLICY_PERMIT);
                }).verifyComplete();
    }
}
