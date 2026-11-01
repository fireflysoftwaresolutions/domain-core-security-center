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

import io.fireflysoftware.security.center.interfaces.access.AccessDecision;
import io.fireflysoftware.security.center.interfaces.access.AccessRequest;
import io.fireflysoftware.security.center.interfaces.identity.Subject;
import io.fireflysoftware.security.center.session.AccessPort;
import io.fireflysoftware.security.center.session.IdentityPort;
import reactor.core.publisher.Mono;

/**
 * Access port that evaluates the subject from {@link IdentityPort}.
 * The delegate does not choose the actor. Realm roles on the subject are passed
 * to the sandbox policy when that adapter is the delegate.
 */
public final class SubjectBoundAccessAdapterImpl implements AccessPort {

    private final IdentityPort identityPort;
    private final AccessPort delegate;
    private final SandboxPolicyAccessAdapterImpl policy;

    public SubjectBoundAccessAdapterImpl(IdentityPort identityPort, AccessPort delegate) {
        this.identityPort = identityPort;
        this.delegate = delegate;
        this.policy = delegate instanceof SandboxPolicyAccessAdapterImpl sandbox ? sandbox : null;
    }

    @Override
    public Mono<AccessDecision> decide(AccessRequest request) {
        if (request == null
                || isBlank(request.getActorId())
                || request.getAction() == null
                || request.getResourceType() == null
                || isBlank(request.getResourceId())) {
            return Mono.just(AccessDecision.denied(AccessDecision.REQUEST_INCOMPLETE));
        }
        return identityPort.resolve(request.getActorId())
                .flatMap(subject -> decideForSubject(request, subject))
                .switchIfEmpty(Mono.just(AccessDecision.denied(AccessDecision.ACTOR_UNKNOWN)));
    }

    private Mono<AccessDecision> decideForSubject(AccessRequest request, Subject subject) {
        AccessRequest bound = AccessRequest.builder()
                .actorId(subject.getActorId())
                .action(request.getAction())
                .resourceType(request.getResourceType())
                .resourceId(request.getResourceId())
                .build();
        if (policy != null) {
            return policy.decide(bound, subject.getRoles());
        }
        return delegate.decide(bound);
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
