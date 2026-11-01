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

package io.fireflysoftware.security.center.core.services;

import org.fireflyframework.security.idp.adapter.IdpAdapter;
import org.fireflyframework.security.idp.dtos.*;
import io.fireflysoftware.security.center.interfaces.identity.IdentityRequest;
import io.fireflysoftware.security.center.session.FireflySessionManager;
import io.fireflysoftware.security.center.session.IdentityPort;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.UUID;

/**
 * Authentication service that orchestrates IDP authentication and Firefly session management.
 * 
 * <p>This service bridges the gap between:
 * <ul>
 *   <li>Identity Provider (Keycloak, AWS Cognito, etc.) - handles authentication</li>
 *   <li>Firefly Session Manager - handles session context and authorization</li>
 * </ul>
 * 
 * <p><strong>Authentication Flow:</strong></p>
 * <pre>
 * 1. User submits credentials to /auth/login
 * 2. Forward credentials to IDP (via IdpAdapter)
 * 3. IDP authenticates and returns tokens
 * 4. Extract user info from IDP
 * 5. Map IDP user to Firefly partyId
 * 6. Create Firefly session with contracts, roles, products
 * 7. Return tokens + sessionId to client
 * </pre>
 */
@Service("authenticationService")
@Slf4j
public class AuthenticationServiceImpl {

    private final IdentityPort identityPort;
    private final FireflySessionManager sessionManager;
    private final IdpAdapter idpAdapter;

    @Autowired(required = false)
    private UserMappingService userMappingService;

    public AuthenticationServiceImpl(
            IdentityPort identityPort,
            FireflySessionManager sessionManager,
            ObjectProvider<IdpAdapter> idpAdapters) {
        this.identityPort = identityPort;
        this.sessionManager = sessionManager;
        this.idpAdapter = idpAdapters.getIfAvailable();
    }

    /**
     * Authenticate user via IDP and create Firefly session
     *
     * @param request Login credentials
     * @return TokenResponse with IDP tokens and Firefly sessionId
     */
    public Mono<AuthenticationResponse> login(LoginRequest request) {
        log.info("Authenticating user: {}", request.getUsername());

        if (idpAdapter == null) {
            return identityPort.authenticate(IdentityRequest.builder()
                            .username(request.getUsername())
                            .password(request.getPassword())
                            .build())
                    .switchIfEmpty(Mono.error(new AuthenticationException("Subject was not recognized")))
                    .map(subject -> AuthenticationResponse.builder()
                            .partyId(UUID.fromString(subject.getActorId()))
                            .tokenType("Bearer")
                            .expiresIn(3600L)
                            .build());
        }

        return idpAdapter.login(request)
                .flatMap(tokenResponse -> {
                    if (tokenResponse.getStatusCode().is2xxSuccessful() && tokenResponse.getBody() != null) {
                        TokenResponse tokens = tokenResponse.getBody();
                        
                        // Get user info from IDP
                        return idpAdapter.getUserInfo(tokens.getAccessToken())
                                .flatMap(userInfoResponse -> {
                                    if (userInfoResponse.getStatusCode().is2xxSuccessful()) {
                                        UserInfoResponse userInfo = userInfoResponse.getBody();
                                        
                                        // Map IDP user to Firefly partyId
                                        return mapUserToPartyId(userInfo, request.getUsername())
                                                .flatMap(partyId -> {
                                                    // Create Firefly session
                                                    return sessionManager.createSession(partyId)
                                                            .map(session -> AuthenticationResponse.builder()
                                                                    .accessToken(tokens.getAccessToken())
                                                                    .refreshToken(tokens.getRefreshToken())
                                                                    .idToken(tokens.getIdToken())
                                                                    .tokenType(tokens.getTokenType())
                                                                    .expiresIn(tokens.getExpiresIn())
                                                                    .sessionId(session.getSessionId())
                                                                    .partyId(partyId)
                                                                    .build());
                                                });
                                    }
                                    return Mono.error(new AuthenticationException("Failed to retrieve user info from IDP"));
                                });
                    }
                    return Mono.error(new AuthenticationException("IDP authentication failed"));
                })
                .doOnSuccess(response -> 
                        log.info("Successfully authenticated user: {}, session: {}", 
                                request.getUsername(), response.getSessionId()))
                .doOnError(error -> 
                        log.error("Authentication failed for user: {}", request.getUsername(), error));
    }

    /**
     * Logout user from both IDP and Firefly session
     *
     * @param logoutRequest Tokens and session info
     * @return Void indicating completion
     */
    public Mono<Void> logout(AuthLogoutRequest logoutRequest) {
        log.info("Logging out session: {}", logoutRequest.getSessionId());

        Mono<Void> idpLogout = idpAdapter == null
                ? Mono.empty()
                : idpAdapter.logout(LogoutRequest.builder()
                        .accessToken(logoutRequest.getAccessToken())
                        .refreshToken(logoutRequest.getRefreshToken())
                        .build());

        // Invalidate Firefly session
        Mono<Void> fireflyLogout = sessionManager.invalidateSession(logoutRequest.getSessionId());

        return Mono.when(idpLogout, fireflyLogout)
                .doOnSuccess(v -> log.info("Successfully logged out session: {}", logoutRequest.getSessionId()))
                .doOnError(error -> log.error("Logout failed for session: {}", logoutRequest.getSessionId(), error));
    }

    /**
     * Refresh IDP tokens and update Firefly session
     *
     * @param request Refresh token
     * @return New TokenResponse with updated tokens
     */
    public Mono<AuthenticationResponse> refresh(RefreshRequest request) {
        log.debug("Refreshing tokens");
        if (idpAdapter == null) {
            return Mono.error(new AuthenticationException("Token refresh requires an identity provider"));
        }

        return idpAdapter.refresh(request)
                .flatMap(tokenResponse -> {
                    if (tokenResponse.getStatusCode().is2xxSuccessful() && tokenResponse.getBody() != null) {
                        TokenResponse tokens = tokenResponse.getBody();
                        
                        // Get updated user info
                        return idpAdapter.getUserInfo(tokens.getAccessToken())
                                .flatMap(userInfoResponse -> {
                                    if (userInfoResponse.getStatusCode().is2xxSuccessful()) {
                                        UserInfoResponse userInfo = userInfoResponse.getBody();
                                        
                                        // Map to partyId and refresh session
                                        return mapUserToPartyId(userInfoResponse.getBody(), UUID.randomUUID().toString())
                                                .flatMap(partyId -> sessionManager.createSession(partyId)
                                                        .map(session -> AuthenticationResponse.builder()
                                                                .accessToken(tokens.getAccessToken())
                                                                .refreshToken(tokens.getRefreshToken())
                                                                .idToken(tokens.getIdToken())
                                                                .tokenType(tokens.getTokenType())
                                                                .expiresIn(tokens.getExpiresIn())
                                                                .sessionId(session.getSessionId())
                                                                .partyId(partyId)
                                                                .build()));
                                    }
                                    return Mono.error(new AuthenticationException("Failed to retrieve user info"));
                                });
                    }
                    return Mono.error(new AuthenticationException("Token refresh failed"));
                })
                .doOnSuccess(response -> log.debug("Successfully refreshed tokens"))
                .doOnError(error -> log.error("Token refresh failed", error));
    }

    /**
     * Introspect IDP token
     */
    public Mono<ResponseEntity<IntrospectionResponse>> introspect(String accessToken) {
        if (idpAdapter == null) {
            return Mono.error(new AuthenticationException("Token introspection requires an identity provider"));
        }
        return idpAdapter.introspect(accessToken);
    }

    /**
     * Reset password for the given user via IDP.
     *
     * @param userName The username whose password will be reset
     * @return completion signal; errors if IDP fails
     */
    public Mono<Void> resetPassword(String userName) {
        log.info("Reset password request for user: {}", userName);
        if (idpAdapter == null) {
            return Mono.error(new AuthenticationException("Password reset requires an identity provider"));
        }
        return idpAdapter.resetPassword(userName)
                .doOnSuccess(v -> log.info("Reset password completed for user: {}", userName))
                .doOnError(err -> log.error("Reset password failed for {}", userName, err));
    }

    /**
     * Map IDP user to Firefly partyId using customer-mgmt SDK.
     *
     * <p>This delegates to {@link UserMappingService} which queries customer-mgmt
     * to find the partyId associated with the IDP user.
     *
     * <p><strong>Mapping Strategies (via DefaultUserMappingService):</strong></p>
     * <ol>
     *   <li>Email-based mapping: Searches all parties' email contacts</li>
     *   <li>Username-based mapping: Searches parties by sourceSystem field</li>
     *   <li>If not found: Throws IllegalStateException - party MUST exist before authentication</li>
     * </ol>
     *
     * <p><strong>Important:</strong> Parties must exist in customer-mgmt before users can authenticate.
     * If a party is not found, authentication will fail with an error.
     *
     * <p><strong>Customization:</strong> Provide your own {@code @Service} implementation
     * of {@link UserMappingService} to override the default behavior (e.g., auto-provision parties).
     *
     * @param userInfo IDP user information from /userinfo endpoint
     * @param username Username from authentication (may be null)
     * @return Mono emitting the partyId
     * @throws IllegalStateException if UserMappingService is not configured or party not found
     */
    private Mono<UUID> mapUserToPartyId(UserInfoResponse userInfo, String username) {
        if (userMappingService == null) {
            log.error("❌ No UserMappingService configured! This should not happen - DefaultUserMappingService should be auto-configured.");
            log.error("❌ Check Spring configuration and ensure customer-mgmt SDK beans are available.");
            return Mono.error(new IllegalStateException(
                    "No UserMappingService configured. Cannot map IDP user to partyId."));
        }

        return userMappingService.mapToPartyId(userInfo, username);
    }

    /**
     * Authentication response with both IDP tokens and Firefly session info
     */
    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class AuthenticationResponse {
        private String accessToken;
        private String refreshToken;
        private String idToken;
        private String tokenType;
        private Long expiresIn;
        private String sessionId;
        private UUID partyId;
    }

    /**
     * Logout request for both IDP and Firefly session
     */
    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class AuthLogoutRequest {
        private String accessToken;
        private String refreshToken;
        private String sessionId;
    }

    /**
     * Authentication exception
     */
    public static class AuthenticationException extends RuntimeException {
        public AuthenticationException(String message) {
            super(message);
        }
        
        public AuthenticationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
