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

import io.fireflysoftware.security.center.interfaces.access.AccessDecision;
import io.fireflysoftware.security.center.interfaces.access.AccessRequest;
import io.fireflysoftware.security.center.session.AccessPort;
import io.fireflysoftware.security.center.core.authorization.ReceiverAuthorization;
import io.fireflysoftware.security.center.interfaces.access.AccessAction;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import java.util.Map;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/**
 * Access check for experience journeys. The decision comes from {@link AccessPort}.
 * Verified caller and current policy admission precede any configured additional restriction.
 */
@ApiResponses({@ApiResponse(responseCode = "401", description = "Verified bearer identity required"),
        @ApiResponse(responseCode = "403", description = "Self actor or current policy refused")})
@SecurityScheme(name = "bearerAuth", type = SecuritySchemeType.HTTP, scheme = "bearer", bearerFormat = "JWT",
        description = "Verified receiver bearer token with the approved issuer, audience, direct client and actor profile")
@SecurityRequirement(name = "bearerAuth")
@RestController
@RequestMapping("/api/v1/access")
@RequiredArgsConstructor
public class AccessController {

    private final AccessPort accessPort;
    private final ReceiverAuthorization authorization;

    /** Caller admission failures use 401/403; an additional configured port can return a restrictive decision. */
    @PostMapping("/checks")
    public Mono<ResponseEntity<AccessDecision>> decideAccess(@Valid @RequestBody AccessRequest request) {
        if (request.getAction() == AccessAction.ADMINISTER || request.getAction() == AccessAction.IMPERSONATE) {
            return Mono.error(new ResponseStatusException(HttpStatus.FORBIDDEN, "Administrative simulation and impersonation are unavailable"));
        }
        return authorization.authorizeSelf(request.getActorId(), request.getAction().name(),
                        request.getResourceType().name() + ":" + request.getResourceId(), Map.of("operation", "security-center.access.check"))
                .flatMap(actor -> Mono.defer(() -> accessPort.decide(request)))
                .map(ResponseEntity::ok);
    }
}
