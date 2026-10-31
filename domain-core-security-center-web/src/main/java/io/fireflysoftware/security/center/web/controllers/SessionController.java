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

import io.fireflysoftware.security.center.core.authorization.ReceiverAuthorization;
import io.fireflysoftware.security.center.interfaces.dtos.SessionContextDTO;
import io.fireflysoftware.security.center.session.FireflySessionManager;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.UUID;

/** Application contexts never authenticate their caller or grant a target party relationship. */
@SecurityRequirement(name = "bearerAuth")
@RestController
@RequestMapping("/api/v1/sessions")
@RequiredArgsConstructor
@ApiResponses({@ApiResponse(responseCode = "401", description = "Verified bearer identity required"),
        @ApiResponse(responseCode = "403", description = "Self party, record ownership or current policy refused")})
public class SessionController {
    private final FireflySessionManager sessionManager;
    private final ReceiverAuthorization authorization;

    @PostMapping
    public Mono<ResponseEntity<SessionContextDTO>> createOrGetSession(ServerWebExchange exchange) {
        UUID requestedParty = null;
        String selectedParty = exchange.getRequest().getHeaders().getFirst("X-Party-Id");
        if (selectedParty != null) {
            try {
                requestedParty = UUID.fromString(selectedParty);
                if (!requestedParty.toString().equals(selectedParty)) throw new IllegalArgumentException();
            } catch (IllegalArgumentException error) {
                return Mono.error(new ResponseStatusException(HttpStatus.BAD_REQUEST, "Canonical party selector required"));
            }
        }
        String selectedSession = exchange.getRequest().getHeaders().getFirst("X-Session-Id");
        String action = selectedSession == null ? "session.create" : "session.read";
        String resource = selectedSession == null ? "session:self" : "session:" + selectedSession;
        return authorization.authorizeParty(requestedParty, action, resource, Map.of())
                .flatMap(actor -> selectedSession == null
                        ? sessionManager.createSession(actor.actorId()).flatMap(session -> owned(session, actor.actorId()))
                        : readOwned(selectedSession, actor.actorId()))
                .map(ResponseEntity::ok).defaultIfEmpty(ResponseEntity.notFound().build());
    }

    @GetMapping("/{sessionId}")
    public Mono<ResponseEntity<SessionContextDTO>> getSessionById(@PathVariable String sessionId) {
        return admittedRecord(sessionId, "session.read").map(ResponseEntity::ok)
                .defaultIfEmpty(ResponseEntity.notFound().build());
    }

    @GetMapping("/party/{partyId}")
    public Mono<ResponseEntity<SessionContextDTO>> getSessionByPartyId(@PathVariable UUID partyId) {
        return authorization.authorizeParty(partyId, "session.read", "party:" + partyId, Map.of())
                .flatMap(actor -> sessionManager.getSessionByPartyId(partyId).flatMap(session -> owned(session, actor.actorId())))
                .map(ResponseEntity::ok).defaultIfEmpty(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/{sessionId}")
    public Mono<ResponseEntity<Void>> invalidateSession(@PathVariable String sessionId) {
        return admittedRecord(sessionId, "session.delete")
                .flatMap(session -> sessionManager.invalidateSession(sessionId).thenReturn(ResponseEntity.noContent().<Void>build()))
                .defaultIfEmpty(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/party/{partyId}")
    public Mono<ResponseEntity<Void>> invalidateSessionsByPartyId(@PathVariable UUID partyId) {
        return authorization.authorizeParty(partyId, "session.delete", "party:" + partyId, Map.of())
                .flatMap(actor -> sessionManager.invalidateSessionsByPartyId(partyId)
                        .thenReturn(ResponseEntity.noContent().<Void>build()));
    }

    @PostMapping("/{sessionId}/refresh")
    public Mono<ResponseEntity<SessionContextDTO>> refreshSession(@PathVariable String sessionId) {
        return admittedRecord(sessionId, "session.refresh").flatMap(original -> sessionManager.refreshSession(sessionId)
                        .flatMap(refreshed -> owned(refreshed, original.getPartyId())))
                .map(ResponseEntity::ok).defaultIfEmpty(ResponseEntity.notFound().build());
    }

    @GetMapping("/{sessionId}/validate")
    public Mono<ResponseEntity<Boolean>> validateSession(@PathVariable String sessionId) {
        return admittedRecord(sessionId, "session.validate").flatMap(sessionManager::isSessionValid)
                .map(ResponseEntity::ok).defaultIfEmpty(ResponseEntity.ok(false));
    }

    @GetMapping("/access-check")
    public Mono<ResponseEntity<Boolean>> checkAccess(@RequestParam UUID partyId, @RequestParam UUID productId) {
        return authorization.authorizeParty(partyId, "session.product.access", "PRODUCT:" + productId, Map.of())
                .flatMap(actor -> sessionManager.hasAccessToProduct(partyId, productId)).map(ResponseEntity::ok);
    }

    @GetMapping("/permission-check")
    public Mono<ResponseEntity<Boolean>> checkPermission(@RequestParam UUID partyId, @RequestParam UUID productId,
            @RequestParam String actionType, @RequestParam(required = false) String resourceType) {
        if (actionType.isBlank()) return Mono.error(new ResponseStatusException(HttpStatus.BAD_REQUEST, "Permission action required"));
        return authorization.authorizeParty(partyId, actionType, "PRODUCT:" + productId,
                        Map.of("operation", "session.product.permission", "resourceType", resourceType == null ? "" : resourceType))
                .flatMap(actor -> sessionManager.hasPermission(partyId, productId, actionType, resourceType)).map(ResponseEntity::ok);
    }

    private Mono<SessionContextDTO> admittedRecord(String sessionId, String action) {
        return authorization.authorizeParty(null, action, "session:" + sessionId, Map.of())
                .flatMap(actor -> readOwned(sessionId, actor.actorId()));
    }

    private Mono<SessionContextDTO> readOwned(String sessionId, UUID party) {
        return sessionManager.getSessionBySessionId(sessionId).flatMap(session -> owned(session, party));
    }

    private Mono<SessionContextDTO> owned(SessionContextDTO session, UUID party) {
        return party.equals(session.getPartyId()) ? Mono.just(session)
                : Mono.error(new ResponseStatusException(HttpStatus.FORBIDDEN, "Self party record required"));
    }
}
