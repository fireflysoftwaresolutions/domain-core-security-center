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

package io.fireflysoftware.security.center.core.identity;

import io.fireflysoftware.security.center.interfaces.identity.IdentityAdapter;
import io.fireflysoftware.security.center.interfaces.identity.IdentityRequest;
import io.fireflysoftware.security.center.interfaces.identity.Subject;
import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;

class SandboxIdentityAdapterTest {

    private final SandboxIdentityAdapterImpl adapter = new SandboxIdentityAdapterImpl();

    @Test
    void sampleUsernameResolvesTheSampleActorWithoutAnIdentityProvider() {
        StepVerifier.create(adapter.authenticate(IdentityRequest.builder().username("sample-journey").password("ignored").build()))
                .assertNext(subject -> assertSample(subject))
                .verifyComplete();
    }

    @Test
    void deniedUsernameResolvesTheSecondActor() {
        StepVerifier.create(adapter.authenticate(IdentityRequest.builder().username("denied-actor").build()))
                .assertNext(subject -> {
                    assertThat(subject.getActorId()).isEqualTo(SandboxIdentityAdapterImpl.DENIED_ACTOR_ID);
                    assertThat(subject.getProvider()).isEqualTo(IdentityAdapter.SANDBOX);
                    assertThat(subject.getRoles()).isEmpty();
                })
                .verifyComplete();
    }

    @Test
    void sampleActorIdResolvesTheSameSubject() {
        StepVerifier.create(adapter.resolve(SandboxIdentityAdapterImpl.SAMPLE_ACTOR_ID.toUpperCase()))
                .assertNext(this::assertSample)
                .verifyComplete();
    }

    @Test
    void sampleEmployeeUsernameReturnsTheEmployeeId() {
        StepVerifier.create(adapter.authenticate(IdentityRequest.builder().username("sample-employee").build()))
                .assertNext(subject -> {
                    assertThat(subject.getActorId()).isEqualTo(SandboxIdentityAdapterImpl.EMPLOYEE_ACTOR_ID);
                    assertThat(subject.getProvider()).isEqualTo(IdentityAdapter.SANDBOX);
                })
                .verifyComplete();
        StepVerifier.create(adapter.resolve(SandboxIdentityAdapterImpl.EMPLOYEE_ACTOR_ID))
                .assertNext(subject -> assertThat(subject.getActorId()).isEqualTo(SandboxIdentityAdapterImpl.EMPLOYEE_ACTOR_ID))
                .verifyComplete();
    }

    @Test
    void unknownUsernameAndActorAreEmpty() {
        StepVerifier.create(adapter.authenticate(IdentityRequest.builder().username("someone-else").build()))
                .verifyComplete();
        StepVerifier.create(adapter.resolve("44444444-4444-4444-8444-444444444444"))
                .verifyComplete();
    }

    private void assertSample(Subject subject) {
        assertThat(subject.getActorId()).isEqualTo(SandboxIdentityAdapterImpl.SAMPLE_ACTOR_ID);
        assertThat(subject.getProvider()).isEqualTo(IdentityAdapter.SANDBOX);
        assertThat(subject.getRoles()).isEmpty();
    }
}
