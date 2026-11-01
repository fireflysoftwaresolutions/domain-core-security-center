/*
 * Copyright 2026 Firefly Software Foundation
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy at https://www.apache.org/licenses/LICENSE-2.0
 * Distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND.
 */
package io.fireflysoftware.security.center.core.authorization;

import io.fireflysoftware.security.center.interfaces.access.AccessDecision;
import io.fireflysoftware.security.center.interfaces.access.AccessRequest;
import io.fireflysoftware.security.center.session.AccessPort;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

import java.util.Objects;

/** A legacy restriction cannot be evaluated before verified caller/current-policy admission. */
public final class AdmittedAccessRestriction implements AccessPort {
    private final CurrentPolicyAccessAdapter admission;
    private final AccessPort restriction;

    public AdmittedAccessRestriction(ReceiverAuthorization authorization, AccessPort restriction) {
        this.admission = new CurrentPolicyAccessAdapter(authorization);
        this.restriction = Objects.requireNonNull(restriction);
    }

    @Override
    public Mono<AccessDecision> decide(AccessRequest request) {
        return admission.decide(request).flatMap(permitted -> Mono.defer(() -> restriction.decide(request))
                .switchIfEmpty(Mono.error(refused()))
                .onErrorMap(error -> refused()));
    }

    private static ResponseStatusException refused() {
        return new ResponseStatusException(HttpStatus.FORBIDDEN, "Additional access restriction unavailable");
    }
}
