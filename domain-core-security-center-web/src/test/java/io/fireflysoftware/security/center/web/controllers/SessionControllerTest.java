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

import io.fireflysoftware.security.center.interfaces.dtos.SessionContextDTO;
import io.fireflysoftware.security.center.session.FireflySessionManager;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import java.util.UUID;

import static org.mockito.Mockito.*;

class SessionControllerTest {
    @Test
    void differentRequestedPartyNeverReadsSessionOrProductContext() {
        FireflySessionManager manager = mock(FireflySessionManager.class);
        WebTestClient.bindToController(new SessionController(manager, ReceiverTestActors.permitted())).build()
                .get().uri("/api/v1/sessions/party/22222222-2222-4222-8222-222222222222")
                .exchange().expectStatus().isForbidden();
        verifyNoInteractions(manager);
    }

    @Test
    void sessionIdCannotReadDeleteOrRefreshAnotherPartysCachedRecord() {
        FireflySessionManager manager = mock(FireflySessionManager.class);
        when(manager.getSessionBySessionId("selected")).thenReturn(Mono.just(SessionContextDTO.builder()
                .sessionId("selected").partyId(UUID.fromString("22222222-2222-4222-8222-222222222222")).build()));
        var client = WebTestClient.bindToController(new SessionController(manager, ReceiverTestActors.permitted())).build();
        client.get().uri("/api/v1/sessions/selected").exchange().expectStatus().isForbidden();
        client.delete().uri("/api/v1/sessions/selected").exchange().expectStatus().isForbidden();
        client.post().uri("/api/v1/sessions/selected/refresh").exchange().expectStatus().isForbidden();
        verify(manager, never()).invalidateSession(anyString());
        verify(manager, never()).refreshSession(anyString());
    }

    @Test
    void absentCallerDoesNotReadCachedRecords() {
        FireflySessionManager manager = mock(FireflySessionManager.class);
        var authorization = ReceiverTestActors.guard(Mono.empty(), (p, a, r, c) ->
                Mono.just(org.fireflyframework.security.api.domain.Decision.permit()));
        WebTestClient.bindToController(new SessionController(manager, authorization)).build()
                .get().uri("/api/v1/sessions/selected").exchange().expectStatus().isUnauthorized();
        verifyNoInteractions(manager);
    }

    @Test
    void selectedMissingSessionIsNotRecreated() {
        FireflySessionManager manager = mock(FireflySessionManager.class);
        when(manager.getSessionBySessionId("missing")).thenReturn(Mono.empty());
        WebTestClient.bindToController(new SessionController(manager, ReceiverTestActors.permitted())).build()
                .post().uri("/api/v1/sessions").header("X-Session-Id", "missing")
                .exchange().expectStatus().isNotFound();
        verify(manager, never()).createSession(any());
        verify(manager, never()).createOrGetSession(any());
    }
}
