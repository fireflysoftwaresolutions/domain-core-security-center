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
import io.fireflysoftware.security.center.session.AccessPort;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

import java.util.Map;

/** The authoritative access path never resolves an actor UUID as an IdP subject. */
public final class CurrentPolicyAccessAdapter implements AccessPort {
    private final ReceiverAuthorization authorization;

    public CurrentPolicyAccessAdapter(ReceiverAuthorization authorization) { this.authorization = authorization; }

    @Override
    public Mono<AccessDecision> decide(AccessRequest request) {
        if (request == null || request.getActorId() == null || request.getAction() == null
                || request.getResourceType() == null || request.getResourceId() == null || request.getResourceId().isBlank()) {
            return Mono.error(new ResponseStatusException(HttpStatus.BAD_REQUEST, "Complete access request required"));
        }
        if (request.getAction() == AccessAction.ADMINISTER || request.getAction() == AccessAction.IMPERSONATE) {
            return Mono.error(new ResponseStatusException(HttpStatus.FORBIDDEN, "Administrative simulation and impersonation are unavailable"));
        }
        return authorization.authorizeSelf(request.getActorId(), request.getAction().name(),
                        request.getResourceType().name() + ":" + request.getResourceId(), Map.of("operation", "security-center.access.check"))
                .map(actor -> AccessDecision.allowed(AccessDecision.CURRENT_POLICY_PERMIT));
    }
}
