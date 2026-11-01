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
import io.fireflysoftware.security.center.session.AccessPort;
import org.fireflyframework.security.api.domain.Decision;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class AccessControllerTest {
    private static final String REQUEST = """
            {"actorId":"11111111-1111-4111-8111-111111111111","action":"READ","resourceType":"ACCOUNT","resourceId":"account-one"}
            """;

    @Test
    void callerPolicyMustPermitBeforeAConfiguredPortCanFurtherRestrict() {
        AccessPort port = mock(AccessPort.class);
        when(port.decide(any())).thenReturn(Mono.just(AccessDecision.denied(AccessDecision.ACTOR_NOT_ENTITLED)));
        WebTestClient.bindToController(new AccessController(port, ReceiverTestActors.permitted())).build()
                .post().uri("/api/v1/access/checks").contentType(MediaType.APPLICATION_JSON).bodyValue(REQUEST)
                .exchange().expectStatus().isOk().expectBody().jsonPath("$.allowed").isEqualTo(false);
        verify(port).decide(any());
    }

    @Test
    void noPrincipalOrCurrentPolicyDenialNeverCallsLegacyEvaluation() {
        AccessPort port = mock(AccessPort.class);
        for (boolean missing : new boolean[]{true, false}) {
            var authorization = ReceiverTestActors.guard(missing ? Mono.empty() : Mono.just(ReceiverTestActors.human()),
                    (p, a, r, c) -> Mono.just(Decision.deny("no current grant")));
            WebTestClient.bindToController(new AccessController(port, authorization)).build()
                    .post().uri("/api/v1/access/checks").contentType(MediaType.APPLICATION_JSON).bodyValue(REQUEST)
                    .exchange().expectStatus().isEqualTo(missing ? 401 : 403);
        }
        verifyNoInteractions(port);
    }

    @Test
    void differentBodyActorAndImpersonationCannotUseAnAllowedTargetPort() {
        AccessPort port = mock(AccessPort.class);
        var client = WebTestClient.bindToController(new AccessController(port, ReceiverTestActors.permitted())).build();
        client.post().uri("/api/v1/access/checks").contentType(MediaType.APPLICATION_JSON)
                .bodyValue(REQUEST.replace(ReceiverTestActors.ACTOR, "22222222-2222-4222-8222-222222222222"))
                .exchange().expectStatus().isForbidden();
        client.post().uri("/api/v1/access/checks").contentType(MediaType.APPLICATION_JSON)
                .bodyValue(REQUEST.replace("READ", "IMPERSONATE")).exchange().expectStatus().isForbidden();
        verifyNoInteractions(port);
    }
}
