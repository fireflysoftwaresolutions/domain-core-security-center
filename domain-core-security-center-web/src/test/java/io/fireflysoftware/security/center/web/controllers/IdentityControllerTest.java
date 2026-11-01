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

import org.fireflyframework.security.api.domain.Decision;
import io.fireflysoftware.security.center.interfaces.identity.IdentityAdapter;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

class IdentityControllerTest {
    @Test
    void signedSelfIsProjectedWithoutAnyUsernameOrIdpLookup() {
        WebTestClient.bindToController(new IdentityController(ReceiverTestActors.permitted(), IdentityAdapter.KEYCLOAK)).build()
                .post().uri("/api/v1/identity/subjects").contentType(MediaType.APPLICATION_JSON).bodyValue("{}")
                .exchange().expectStatus().isOk().expectBody()
                .jsonPath("$.actorId").isEqualTo(ReceiverTestActors.ACTOR)
                .jsonPath("$.provider").isEqualTo("keycloak")
                .jsonPath("$.roles[0]").isEqualTo("signed-profile-reader")
                .jsonPath("$.accessToken").doesNotExist();
    }

    @Test
    void usernameOnlyOrPasswordRequestsAreNotAuthentication() {
        var client = WebTestClient.bindToController(new IdentityController(ReceiverTestActors.permitted(), IdentityAdapter.KEYCLOAK)).build();
        for (String request : new String[]{"{\"username\":\"known-admin\"}", "{\"password\":\"private-secret\"}"}) {
            client.post().uri("/api/v1/identity/subjects").contentType(MediaType.APPLICATION_JSON).bodyValue(request)
                    .exchange().expectStatus().isBadRequest();
        }
    }

    @Test
    void absentPrincipalWrongActorAndCurrentPolicyRefusalCannotReturnAnIdentity() {
        var absent = ReceiverTestActors.guard(Mono.empty(), (p, a, r, c) -> Mono.just(Decision.permit()));
        WebTestClient.bindToController(new IdentityController(absent, IdentityAdapter.KEYCLOAK)).build()
                .post().uri("/api/v1/identity/subjects").contentType(MediaType.APPLICATION_JSON).bodyValue("{}")
                .exchange().expectStatus().isUnauthorized();
        var client = WebTestClient.bindToController(new IdentityController(ReceiverTestActors.permitted(), IdentityAdapter.KEYCLOAK)).build();
        client.post().uri("/api/v1/identity/subjects").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"actorId\":\"22222222-2222-4222-8222-222222222222\"}")
                .exchange().expectStatus().isForbidden();
        var denied = ReceiverTestActors.guard(Mono.just(ReceiverTestActors.human()), (p, a, r, c) -> Mono.just(Decision.deny("denied")));
        WebTestClient.bindToController(new IdentityController(denied, IdentityAdapter.KEYCLOAK)).build()
                .post().uri("/api/v1/identity/subjects").contentType(MediaType.APPLICATION_JSON).bodyValue("{}")
                .exchange().expectStatus().isForbidden();
    }
}
