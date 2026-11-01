/*
 * Copyright 2025 Firefly Software Foundation
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

import org.fireflyframework.security.idp.dtos.LoginRequest;
import org.fireflyframework.security.idp.dtos.RefreshRequest;
import io.fireflysoftware.security.center.core.services.AuthenticationServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Unit tests for AuthenticationController
 * 
 * <p>Tests the controller layer in isolation with mocked AuthenticationService:
 * <ul>
 *   <li>Login with valid credentials</li>
 *   <li>Login with invalid credentials</li>
 *   <li>Logout</li>
 *   <li>Token refresh</li>
 *   <li>Token introspection</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class AuthenticationControllerIntegrationTest {

    @Mock
    private AuthenticationServiceImpl authenticationService;

    @InjectMocks
    private AuthenticationController controller;

    @BeforeEach
    void setUp() {
        // Setup is done per test
    }

    @Test
    void testLoginSuccess() {
        // Arrange
        LoginRequest request = LoginRequest.builder()
                .username("test_user")
                .password("test_password")
                .build();

        AuthenticationServiceImpl.AuthenticationResponse mockResponse = AuthenticationServiceImpl.AuthenticationResponse.builder()
                .accessToken("mock_access_token")
                .refreshToken("mock_refresh_token")
                .idToken("mock_id_token")
                .tokenType("Bearer")
                .expiresIn(3600L)
                .sessionId("session_123")
                .partyId(UUID.randomUUID())
                .build();

        when(authenticationService.login(any(LoginRequest.class)))
                .thenReturn(Mono.just(mockResponse));

        // Act
        Mono<ResponseEntity<AuthenticationServiceImpl.AuthenticationResponse>> result = controller.login(request);

        // Assert
        StepVerifier.create(result)
                .assertNext(response -> {
                    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
                    assertThat(response.getBody()).isNotNull();
                    assertThat(response.getBody().getAccessToken()).isEqualTo("mock_access_token");
                    assertThat(response.getBody().getRefreshToken()).isEqualTo("mock_refresh_token");
                    assertThat(response.getBody().getSessionId()).isEqualTo("session_123");
                    assertThat(response.getBody().getTokenType()).isEqualTo("Bearer");
                })
                .verifyComplete();
    }

    @Test
    void testLoginFailure() {
        // Arrange
        LoginRequest request = LoginRequest.builder()
                .username("bad_user")
                .password("bad_password")
                .build();

        when(authenticationService.login(any(LoginRequest.class)))
                .thenReturn(Mono.error(new AuthenticationServiceImpl.AuthenticationException("Invalid credentials")));

        // Act
        Mono<ResponseEntity<AuthenticationServiceImpl.AuthenticationResponse>> result = controller.login(request);

        // Assert  - Controller handles error and returns 401 response
        StepVerifier.create(result)
                .assertNext(response -> {
                    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
                })
                .verifyComplete();
    }

    @Test
    void testLogoutSuccess() {
        // Arrange
        AuthenticationServiceImpl.AuthLogoutRequest request = AuthenticationServiceImpl.AuthLogoutRequest.builder()
                .accessToken("mock_access_token")
                .refreshToken("mock_refresh_token")
                .sessionId("session_123")
                .build();

        when(authenticationService.logout(any(AuthenticationServiceImpl.AuthLogoutRequest.class)))
                .thenReturn(Mono.empty());

        // Act
        Mono<ResponseEntity<Void>> result = controller.logout(request);

        // Assert
        StepVerifier.create(result)
                .assertNext(response -> {
                    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
                })
                .verifyComplete();
    }

    @Test
    void testTokenRefreshSuccess() {
        // Arrange
        RefreshRequest request = RefreshRequest.builder()
                .refreshToken("mock_refresh_token")
                .build();

        AuthenticationServiceImpl.AuthenticationResponse mockResponse = AuthenticationServiceImpl.AuthenticationResponse.builder()
                .accessToken("new_access_token")
                .refreshToken("new_refresh_token")
                .idToken("new_id_token")
                .tokenType("Bearer")
                .expiresIn(3600L)
                .sessionId("session_123")
                .partyId(UUID.randomUUID())
                .build();

        when(authenticationService.refresh(any(RefreshRequest.class)))
                .thenReturn(Mono.just(mockResponse));

        // Act
        Mono<ResponseEntity<AuthenticationServiceImpl.AuthenticationResponse>> result = controller.refresh(request);

        // Assert
        StepVerifier.create(result)
                .assertNext(response -> {
                    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
                    assertThat(response.getBody()).isNotNull();
                    assertThat(response.getBody().getAccessToken()).isEqualTo("new_access_token");
                    assertThat(response.getBody().getRefreshToken()).isEqualTo("new_refresh_token");
                })
                .verifyComplete();
    }

}
