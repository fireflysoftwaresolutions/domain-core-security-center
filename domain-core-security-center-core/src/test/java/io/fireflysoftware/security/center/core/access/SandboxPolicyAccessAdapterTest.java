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

import io.fireflysoftware.security.center.interfaces.access.AccessAction;
import io.fireflysoftware.security.center.interfaces.access.AccessDecision;
import io.fireflysoftware.security.center.interfaces.access.AccessRequest;
import io.fireflysoftware.security.center.interfaces.access.AccessResourceType;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.core.io.DefaultResourceLoader;
import reactor.test.StepVerifier;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SandboxPolicyAccessAdapterTest {

    static final String SAMPLE_ACTOR = "11111111-1111-4111-8111-111111111111";
    static final String DENIED_ACTOR = "22222222-2222-4222-8222-222222222222";
    static final String EMPLOYEE_ACTOR = "33333333-3333-4333-8333-333333333333";

    static final Map<AccessResourceType, String> SAMPLE_RESOURCES = Map.of(
            AccessResourceType.PARTY, "10000000-0000-4000-8000-000000000001",
            AccessResourceType.ACCOUNT, "10000000-0000-4000-8000-000000000002",
            AccessResourceType.CARD, "10000000-0000-4000-8000-000000000003",
            AccessResourceType.APPLICATION, "10000000-0000-4000-8000-000000000004",
            AccessResourceType.POLICY, "10000000-0000-4000-8000-000000000005",
            AccessResourceType.CLAIM, "10000000-0000-4000-8000-000000000006",
            AccessResourceType.CONTRACT, "10000000-0000-4000-8000-000000000007",
            AccessResourceType.PRODUCT, "10000000-0000-4000-8000-000000000008",
            AccessResourceType.PAYMENT, "10000000-0000-4000-8000-0000000000a1");

    static SandboxPolicyAccessAdapterImpl shipped;

    @BeforeAll
    static void loadShippedPolicy() {
        shipped = new SandboxPolicyAccessAdapterImpl(new DefaultResourceLoader(), SandboxPolicyAccessAdapterImpl.DEFAULT_LOCATION);
    }

    @ParameterizedTest
    @EnumSource(AccessResourceType.class)
    void sampleActorMayReadEachSampleResource(AccessResourceType resourceType) {
        assertDecision(
                shipped,
                request(SAMPLE_ACTOR, AccessAction.READ, resourceType, SAMPLE_RESOURCES.get(resourceType)),
                true,
                AccessDecision.SANDBOX_GRANT);
    }

    @ParameterizedTest
    @EnumSource(AccessResourceType.class)
    void sampleActorMayCreateEachSampleResource(AccessResourceType resourceType) {
        assertDecision(
                shipped,
                request(SAMPLE_ACTOR, AccessAction.CREATE, resourceType, SAMPLE_RESOURCES.get(resourceType)),
                true,
                AccessDecision.SANDBOX_GRANT);
    }

    @ParameterizedTest
    @EnumSource(value = AccessAction.class, names = {"CLOSE", "DECIDE", "ADMINISTER", "IMPERSONATE"})
    void sampleActorMayNotStaffOrLifecycleActions(AccessAction action) {
        assertDecision(
                shipped,
                request(SAMPLE_ACTOR, action, AccessResourceType.ACCOUNT, SAMPLE_RESOURCES.get(AccessResourceType.ACCOUNT)),
                false,
                AccessDecision.ACTION_NOT_GRANTED);
    }

    @Test
    void sampleActorMayUpdateAnApplication() {
        assertDecision(
                shipped,
                request(SAMPLE_ACTOR, AccessAction.UPDATE, AccessResourceType.APPLICATION, "a7616543-a336-4af9-814e-6ccc1d182ce0"),
                true,
                AccessDecision.SANDBOX_GRANT);
    }

    @Test
    void sampleActorMayNotUpdateAnAccount() {
        assertDecision(
                shipped,
                request(SAMPLE_ACTOR, AccessAction.UPDATE, AccessResourceType.ACCOUNT, SAMPLE_RESOURCES.get(AccessResourceType.ACCOUNT)),
                false,
                AccessDecision.RESOURCE_NOT_GRANTED);
    }

    @Test
    void sampleActorMayNotReadADifferentResource() {
        assertDecision(
                shipped,
                request(SAMPLE_ACTOR, AccessAction.READ, AccessResourceType.ACCOUNT, SAMPLE_RESOURCES.get(AccessResourceType.PARTY)),
                false,
                AccessDecision.RESOURCE_NOT_GRANTED);
    }

    @Test
    void secondActorIsDeniedReadAndCreate() {
        assertDecision(
                shipped,
                request(DENIED_ACTOR, AccessAction.READ, AccessResourceType.ACCOUNT, SAMPLE_RESOURCES.get(AccessResourceType.ACCOUNT)),
                false,
                AccessDecision.ACTOR_NOT_ENTITLED);
        assertDecision(
                shipped,
                request(DENIED_ACTOR, AccessAction.CREATE, AccessResourceType.PARTY, SAMPLE_RESOURCES.get(AccessResourceType.PARTY)),
                false,
                AccessDecision.ACTOR_NOT_ENTITLED);
    }

    @Test
    void unknownActorIsDenied() {
        assertDecision(
                shipped,
                request("44444444-4444-4444-8444-444444444444", AccessAction.READ, AccessResourceType.PARTY, SAMPLE_RESOURCES.get(AccessResourceType.PARTY)),
                false,
                AccessDecision.ACTOR_UNKNOWN);
    }

    @ParameterizedTest
    @EnumSource(AccessResourceType.class)
    void employeeMayReadEachSampleResource(AccessResourceType resourceType) {
        assertDecision(
                shipped,
                request(EMPLOYEE_ACTOR, AccessAction.READ, resourceType, SAMPLE_RESOURCES.get(resourceType)),
                true,
                AccessDecision.SANDBOX_GRANT);
    }

    @ParameterizedTest
    @EnumSource(value = AccessAction.class, names = {"ADMINISTER", "IMPERSONATE"})
    void employeeMayAdministerAndImpersonate(AccessAction action) {
        assertDecision(
                shipped,
                request(EMPLOYEE_ACTOR, action, AccessResourceType.ACCOUNT, SAMPLE_RESOURCES.get(AccessResourceType.ACCOUNT)),
                true,
                AccessDecision.SANDBOX_GRANT);
    }

    @Test
    void employeeMayNotCreate() {
        assertDecision(
                shipped,
                request(EMPLOYEE_ACTOR, AccessAction.CREATE, AccessResourceType.ACCOUNT, SAMPLE_RESOURCES.get(AccessResourceType.ACCOUNT)),
                false,
                AccessDecision.ACTION_NOT_GRANTED);
    }

    @Test
    void actorAndResourceIdsAreComparedWithoutCase() {
        assertDecision(
                shipped,
                request(SAMPLE_ACTOR.toUpperCase(), AccessAction.READ, AccessResourceType.CARD, SAMPLE_RESOURCES.get(AccessResourceType.CARD).toUpperCase()),
                true,
                AccessDecision.SANDBOX_GRANT);
    }

    @Test
    void incompleteRequestIsDenied() {
        assertDecision(shipped, AccessRequest.builder().actorId(SAMPLE_ACTOR).build(), false, AccessDecision.REQUEST_INCOMPLETE);
        assertDecision(shipped, null, false, AccessDecision.REQUEST_INCOMPLETE);
    }

    @Test
    void replacedPolicyFileChangesWhoIsAllowed() throws Exception {
        Path file = Files.createTempFile("sandbox-access-policy", ".json");
        Files.writeString(file, """
                {
                  "actors": [
                    {
                      "actorId": "22222222-2222-4222-8222-222222222222",
                      "grants": [
                        {"action": "READ", "resourceType": "ACCOUNT", "resourceId": "10000000-0000-4000-8000-000000000002"}
                      ]
                    }
                  ]
                }
                """);

        SandboxPolicyAccessAdapterImpl replaced = new SandboxPolicyAccessAdapterImpl(
                new DefaultResourceLoader(), file.toUri().toString());

        assertDecision(
                replaced,
                request(DENIED_ACTOR, AccessAction.READ, AccessResourceType.ACCOUNT, SAMPLE_RESOURCES.get(AccessResourceType.ACCOUNT)),
                true,
                AccessDecision.SANDBOX_GRANT);
        assertDecision(
                replaced,
                request(SAMPLE_ACTOR, AccessAction.READ, AccessResourceType.ACCOUNT, SAMPLE_RESOURCES.get(AccessResourceType.ACCOUNT)),
                false,
                AccessDecision.ACTOR_UNKNOWN);
    }

    @Test
    void wildcardResourceIdInAReplacedFileGrantsEveryIdOfThatType() throws Exception {
        Path file = Files.createTempFile("sandbox-access-policy", ".json");
        Files.writeString(file, """
                {
                  "actors": [
                    {
                      "actorId": "33333333-3333-4333-8333-333333333333",
                      "grants": [
                        {"action": "DECIDE", "resourceType": "APPLICATION", "resourceId": "*"}
                      ]
                    }
                  ]
                }
                """);

        SandboxPolicyAccessAdapterImpl replaced = new SandboxPolicyAccessAdapterImpl(
                new DefaultResourceLoader(), file.toUri().toString());

        assertDecision(
                replaced,
                request("33333333-3333-4333-8333-333333333333", AccessAction.DECIDE, AccessResourceType.APPLICATION, "any-application"),
                true,
                AccessDecision.SANDBOX_GRANT);
        assertDecision(
                replaced,
                request("33333333-3333-4333-8333-333333333333", AccessAction.READ, AccessResourceType.APPLICATION, "any-application"),
                false,
                AccessDecision.ACTION_NOT_GRANTED);
    }

    @Test
    void missingPolicyFileFailsAtStartup() {
        assertThatThrownBy(() -> new SandboxPolicyAccessAdapterImpl(
                new DefaultResourceLoader(), "classpath:access/missing-sandbox-access-policy.json"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not found");
    }

    @Test
    void malformedPolicyFileFailsAtStartup() throws Exception {
        Path file = Files.createTempFile("sandbox-access-policy", ".json");
        Files.writeString(file, "{");

        assertThatThrownBy(() -> new SandboxPolicyAccessAdapterImpl(new DefaultResourceLoader(), file.toUri().toString()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("could not be read");
    }

    private static void assertDecision(
            SandboxPolicyAccessAdapterImpl adapter,
            AccessRequest request,
            boolean allowed,
            String reasonCode) {
        StepVerifier.create(adapter.decide(request))
                .assertNext(decision -> {
                    assertThat(decision.isAllowed()).isEqualTo(allowed);
                    assertThat(decision.getReasonCode()).isEqualTo(reasonCode);
                })
                .verifyComplete();
    }

    private static AccessRequest request(
            String actorId,
            AccessAction action,
            AccessResourceType resourceType,
            String resourceId) {
        return AccessRequest.builder()
                .actorId(actorId)
                .action(action)
                .resourceType(resourceType)
                .resourceId(resourceId)
                .build();
    }
}
