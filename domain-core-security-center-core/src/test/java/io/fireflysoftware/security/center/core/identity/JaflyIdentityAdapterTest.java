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
import org.fireflyframework.security.idp.adapter.IdpAdapter;
import org.fireflyframework.security.idp.dtos.LoginRequest;
import org.fireflyframework.security.idp.dtos.TokenResponse;
import org.fireflyframework.security.idp.dtos.UserInfoResponse;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class JaflyIdentityAdapterTest {

    @Test
    void keycloakSubjectComesFromTheJaflyAdapterAndItsRealmRoles() {
        IdpAdapter idpAdapter = mock(IdpAdapter.class);
        when(idpAdapter.login(any(LoginRequest.class))).thenReturn(Mono.just(ResponseEntity.ok(
                TokenResponse.builder().accessToken("access-token").build())));
        when(idpAdapter.getUserInfo("access-token")).thenReturn(Mono.just(ResponseEntity.ok(
                UserInfoResponse.builder().sub("user-subject").preferredUsername("user").build())));
        when(idpAdapter.getRoles("user-subject")).thenReturn(Mono.just(ResponseEntity.ok(List.of("account-reader"))));

        JaflyIdentityAdapterImpl adapter = new JaflyIdentityAdapterImpl(idpAdapter, IdentityAdapter.KEYCLOAK);

        StepVerifier.create(adapter.authenticate(IdentityRequest.builder().username("user").password("secret").build()))
                .assertNext(subject -> {
                    assertThat(subject.getActorId()).isEqualTo("user-subject");
                    assertThat(subject.getProvider()).isEqualTo(IdentityAdapter.KEYCLOAK);
                    assertThat(subject.getRoles()).containsExactly("account-reader");
                })
                .verifyComplete();

        verify(idpAdapter).login(any(LoginRequest.class));
    }

    @Test
    void resolveStillReturnsTheSubjectWhenRealmRolesAreUnsupported() {
        IdpAdapter idpAdapter = mock(IdpAdapter.class);
        when(idpAdapter.getRoles("actor-1")).thenReturn(Mono.error(new UnsupportedOperationException("getRoles")));

        JaflyIdentityAdapterImpl adapter = new JaflyIdentityAdapterImpl(idpAdapter, IdentityAdapter.COGNITO);

        StepVerifier.create(adapter.resolve("actor-1"))
                .assertNext(subject -> {
                    assertThat(subject.getActorId()).isEqualTo("actor-1");
                    assertThat(subject.getProvider()).isEqualTo(IdentityAdapter.COGNITO);
                    assertThat(subject.getRoles()).isEmpty();
                })
                .verifyComplete();
    }
}
