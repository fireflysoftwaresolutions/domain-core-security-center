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
import io.fireflysoftware.security.center.session.IdentityPort;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Locale;

/**
 * Identity adapter for the OpenPlatform sample. It does not call Keycloak,
 * Cognito, or any other identity provider, and it does not read a password.
 */
public final class SandboxIdentityAdapterImpl implements IdentityPort {

    public static final String SAMPLE_USERNAME = "sample-journey";
    public static final String DENIED_USERNAME = "denied-actor";
    public static final String EMPLOYEE_USERNAME = "sample-employee";
    public static final String SAMPLE_ACTOR_ID = "11111111-1111-4111-8111-111111111111";
    public static final String DENIED_ACTOR_ID = "22222222-2222-4222-8222-222222222222";
    public static final String EMPLOYEE_ACTOR_ID = "33333333-3333-4333-8333-333333333333";

    @Override
    public Mono<Subject> authenticate(IdentityRequest request) {
        if (request == null || isBlank(request.getUsername())) {
            return Mono.empty();
        }
        return subjectForUsername(request.getUsername());
    }

    @Override
    public Mono<Subject> resolve(String actorId) {
        if (isBlank(actorId)) {
            return Mono.empty();
        }
        String normalized = normalize(actorId);
        if (SAMPLE_ACTOR_ID.equals(normalized)) {
            return Mono.just(subject(SAMPLE_ACTOR_ID));
        }
        if (DENIED_ACTOR_ID.equals(normalized)) {
            return Mono.just(subject(DENIED_ACTOR_ID));
        }
        if (EMPLOYEE_ACTOR_ID.equals(normalized)) {
            return Mono.just(subject(EMPLOYEE_ACTOR_ID));
        }
        return Mono.empty();
    }

    private static Mono<Subject> subjectForUsername(String username) {
        String normalized = normalize(username);
        if (SAMPLE_USERNAME.equals(normalized)) {
            return Mono.just(subject(SAMPLE_ACTOR_ID));
        }
        if (DENIED_USERNAME.equals(normalized)) {
            return Mono.just(subject(DENIED_ACTOR_ID));
        }
        if (EMPLOYEE_USERNAME.equals(normalized)) {
            return Mono.just(subject(EMPLOYEE_ACTOR_ID));
        }
        return Mono.empty();
    }

    private static Subject subject(String actorId) {
        return Subject.builder()
                .actorId(actorId)
                .provider(IdentityAdapter.SANDBOX)
                .roles(List.of())
                .build();
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private static String normalize(String value) {
        return value.trim().toLowerCase(Locale.ROOT);
    }
}
