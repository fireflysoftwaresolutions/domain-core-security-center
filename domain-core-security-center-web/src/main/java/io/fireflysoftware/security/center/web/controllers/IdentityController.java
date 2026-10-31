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

import io.fireflysoftware.security.center.interfaces.identity.IdentityRequest;
import io.fireflysoftware.security.center.interfaces.identity.Subject;
import io.fireflysoftware.security.center.core.authorization.ReceiverAuthorization;
import io.fireflysoftware.security.center.interfaces.identity.IdentityAdapter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/**
 * Projects the independently verified direct self actor without identity-provider lookup.
 */
@ApiResponses({@ApiResponse(responseCode = "401", description = "Verified bearer identity required"),
        @ApiResponse(responseCode = "403", description = "Self actor or current policy refused")})
@SecurityRequirement(name = "bearerAuth")
@RestController
@RequestMapping("/api/v1/identity")
public class IdentityController {

    private final ReceiverAuthorization authorization;
    private final IdentityAdapter adapter;

    public IdentityController(ReceiverAuthorization authorization, IdentityAdapter adapter) {
        this.authorization = authorization;
        this.adapter = adapter;
    }

    /** Returns only verified self identity; username/password bodies are unsupported. */
    @PostMapping("/subjects")
    public Mono<ResponseEntity<Subject>> subject(@RequestBody IdentityRequest request) {
        if (request == null || !isBlank(request.getUsername()) || !isBlank(request.getPassword())) {
            return Mono.just(ResponseEntity.badRequest().build());
        }
        return authorization.authorizeSelf(isBlank(request.getActorId()) ? null : request.getActorId(),
                        "identity.subject.read", "identity:self", Map.of("operation", "security-center.identity.subject"))
                .map(actor -> ResponseEntity.ok(Subject.builder().actorId(actor.actorId().toString())
                        .provider(adapter).roles(actor.principal().authorities().stream().sorted().toList()).build()));
    }

    private static boolean isBlank(String value) { return value == null || value.isBlank(); }
}
