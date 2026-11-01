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

package io.fireflysoftware.security.center.core.access;

import io.fireflysoftware.security.center.core.identity.SandboxIdentityAdapterImpl;
import io.fireflysoftware.security.center.interfaces.identity.IdentityAdapter;
import io.fireflysoftware.security.center.interfaces.access.AccessAction;
import io.fireflysoftware.security.center.interfaces.access.AccessDecision;
import io.fireflysoftware.security.center.interfaces.access.AccessRequest;
import io.fireflysoftware.security.center.interfaces.access.AccessResourceType;
import io.fireflysoftware.security.center.interfaces.identity.IdentityRequest;
import io.fireflysoftware.security.center.interfaces.identity.Subject;
import io.fireflysoftware.security.center.session.IdentityPort;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.DefaultResourceLoader;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SubjectBoundAccessAdapterTest {

    @Test
    void usesTheSandboxSubjectAndAllowsOnlyTheSampleActor() {
        SandboxPolicyAccessAdapterImpl policy = new SandboxPolicyAccessAdapterImpl(
                new DefaultResourceLoader(), SandboxPolicyAccessAdapterImpl.DEFAULT_LOCATION);
        SubjectBoundAccessAdapterImpl access = new SubjectBoundAccessAdapterImpl(new SandboxIdentityAdapterImpl(), policy);

        assertDecision(access, SandboxIdentityAdapterImpl.SAMPLE_ACTOR_ID, AccessAction.READ, true, AccessDecision.SANDBOX_GRANT);
        assertDecision(access, SandboxIdentityAdapterImpl.SAMPLE_ACTOR_ID, AccessAction.CREATE, true, AccessDecision.SANDBOX_GRANT);
        assertDecision(access, SandboxIdentityAdapterImpl.DENIED_ACTOR_ID, AccessAction.READ, false, AccessDecision.ACTOR_NOT_ENTITLED);
        assertDecision(access, SandboxIdentityAdapterImpl.SAMPLE_ACTOR_ID, AccessAction.ADMINISTER, false, AccessDecision.ACTION_NOT_GRANTED);
        assertDecision(access, SandboxIdentityAdapterImpl.SAMPLE_ACTOR_ID, AccessAction.IMPERSONATE, false, AccessDecision.ACTION_NOT_GRANTED);
        assertDecision(access, SandboxIdentityAdapterImpl.EMPLOYEE_ACTOR_ID, AccessAction.READ, true, AccessDecision.SANDBOX_GRANT);
        assertDecision(access, SandboxIdentityAdapterImpl.EMPLOYEE_ACTOR_ID, AccessAction.ADMINISTER, true, AccessDecision.SANDBOX_GRANT);
        assertDecision(access, SandboxIdentityAdapterImpl.EMPLOYEE_ACTOR_ID, AccessAction.IMPERSONATE, true, AccessDecision.SANDBOX_GRANT);
        assertDecision(access, "44444444-4444-4444-8444-444444444444", AccessAction.READ, false, AccessDecision.ACTOR_UNKNOWN);
    }

    @Test
    void realmRoleOnTheSubjectSatisfiesARoleGrantInAReplacedPolicy() throws Exception {
        Path file = Files.createTempFile("sandbox-access-policy", ".json");
        Files.writeString(file, """
                {
                  "actors": [],
                  "roles": [
                    {
                      "role": "account-reader",
                      "grants": [
                        {"action": "READ", "resourceType": "ACCOUNT", "resourceId": "*"}
                      ]
                    }
                  ]
                }
                """);
        SandboxPolicyAccessAdapterImpl policy = new SandboxPolicyAccessAdapterImpl(new DefaultResourceLoader(), file.toUri().toString());
        IdentityPort identity = new IdentityPort() {
            @Override
            public Mono<Subject> authenticate(IdentityRequest request) {
                return Mono.empty();
            }

            @Override
            public Mono<Subject> resolve(String actorId) {
                return Mono.just(Subject.builder()
                        .actorId(actorId)
                        .provider(IdentityAdapter.KEYCLOAK)
                        .roles(List.of("account-reader"))
                        .build());
            }
        };
        SubjectBoundAccessAdapterImpl access = new SubjectBoundAccessAdapterImpl(identity, policy);

        assertDecision(access, "keycloak-user", AccessAction.READ, true, AccessDecision.REALM_ROLE_GRANT);
        assertDecision(access, "keycloak-user", AccessAction.CREATE, false, AccessDecision.ACTOR_UNKNOWN);
    }

    private static void assertDecision(
            SubjectBoundAccessAdapterImpl access,
            String actorId,
            AccessAction action,
            boolean allowed,
            String reasonCode) {
        AccessRequest request = AccessRequest.builder()
                .actorId(actorId)
                .action(action)
                .resourceType(AccessResourceType.ACCOUNT)
                .resourceId("10000000-0000-4000-8000-000000000002")
                .build();
        StepVerifier.create(access.decide(request))
                .assertNext(decision -> {
                    assertThat(decision.isAllowed()).isEqualTo(allowed);
                    assertThat(decision.getReasonCode()).isEqualTo(reasonCode);
                })
                .verifyComplete();
    }
}
