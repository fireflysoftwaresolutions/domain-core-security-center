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
import io.fireflysoftware.security.center.interfaces.identity.Subject;
import io.fireflysoftware.security.center.session.IdentityPort;
import org.fireflyframework.security.idp.adapter.IdpAdapter;
import org.fireflyframework.security.idp.dtos.LoginRequest;
import org.fireflyframework.security.idp.dtos.TokenResponse;
import org.fireflyframework.security.idp.dtos.UserInfoResponse;
import org.springframework.http.ResponseEntity;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * Identity adapter that delegates to the Jafly {@link IdpAdapter} already selected
 * for the deployment. Keycloak's reference implementation is
 * {@code org.fireflyframework.security.idp.adapter.impl.IdpAdapterImpl}
 * from {@code org.fireflyframework:fireflyframework-security-idp-keycloak}.
 * Cognito and the internal database adapter implement the same port.
 * This class does not open its own Keycloak client.
 */
public final class JaflyIdentityAdapterImpl implements IdentityPort {

    private final IdpAdapter idpAdapter;
    private final IdentityAdapter adapter;

    public JaflyIdentityAdapterImpl(IdpAdapter idpAdapter, IdentityAdapter adapter) {
        this.idpAdapter = idpAdapter;
        this.adapter = adapter;
    }

    @Override
    public Mono<Subject> authenticate(IdentityRequest request) {
        if (request == null || isBlank(request.getUsername())) {
            return Mono.empty();
        }
        LoginRequest login = LoginRequest.builder()
                .username(request.getUsername())
                .password(request.getPassword())
                .build();
        return idpAdapter.login(login)
                .flatMap(this::userInfo)
                .flatMap(info -> {
                    String actorId = actorId(info);
                    if (isBlank(actorId)) {
                        return Mono.empty();
                    }
                    return rolesOf(actorId).map(roles -> subject(actorId, roles));
                });
    }

    @Override
    public Mono<Subject> resolve(String actorId) {
        if (isBlank(actorId)) {
            return Mono.empty();
        }
        String subjectId = actorId.trim();
        return rolesOf(subjectId).map(roles -> subject(subjectId, roles));
    }

    private Mono<UserInfoResponse> userInfo(ResponseEntity<TokenResponse> tokenResponse) {
        if (tokenResponse == null || tokenResponse.getBody() == null || isBlank(tokenResponse.getBody().getAccessToken())) {
            return Mono.empty();
        }
        return idpAdapter.getUserInfo(tokenResponse.getBody().getAccessToken())
                .flatMap(response -> response == null || response.getBody() == null
                        ? Mono.empty()
                        : Mono.just(response.getBody()));
    }

    private Mono<List<String>> rolesOf(String actorId) {
        return idpAdapter.getRoles(actorId)
                .map(response -> response != null && response.getBody() != null ? List.copyOf(response.getBody()) : List.<String>of())
                .onErrorReturn(List.of());
    }

    private Subject subject(String actorId, List<String> roles) {
        return Subject.builder()
                .actorId(actorId)
                .provider(adapter)
                .roles(roles == null ? List.of() : roles)
                .build();
    }

    private static String actorId(UserInfoResponse info) {
        if (!isBlank(info.getSub())) {
            return info.getSub().trim();
        }
        if (!isBlank(info.getPreferredUsername())) {
            return info.getPreferredUsername().trim();
        }
        return null;
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
