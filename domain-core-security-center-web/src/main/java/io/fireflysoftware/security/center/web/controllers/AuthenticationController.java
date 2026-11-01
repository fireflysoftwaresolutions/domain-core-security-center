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

import org.fireflyframework.security.idp.dtos.IntrospectionResponse;
import org.fireflyframework.security.idp.dtos.LoginRequest;
import org.fireflyframework.security.idp.dtos.RefreshRequest;
import io.fireflysoftware.security.center.core.services.AuthenticationServiceImpl;
import io.fireflysoftware.security.center.core.services.AuthenticationServiceImpl.AuthLogoutRequest;
import io.fireflysoftware.security.center.core.services.AuthenticationServiceImpl.AuthenticationResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

/**
 * REST controller for authentication operations.
 * 
 * <p>Integrates Identity Provider (IDP) authentication with Firefly session management.
 * 
 * <p><strong>Authentication Flow:</strong></p>
 * <ol>
 *   <li>Client calls /auth/login with credentials</li>
 *   <li>Security Center authenticates via IDP (Keycloak/Cognito/etc.)</li>
 *   <li>IDP returns access/refresh/id tokens</li>
 *   <li>Security Center creates Firefly session with contracts/roles/products</li>
 *   <li>Returns tokens + sessionId to client</li>
 *   <li>Client uses tokens for API calls + sessionId for authorization</li>
 * </ol>
 */
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthenticationController {

    private final AuthenticationServiceImpl authenticationService;

    /**
     * Login endpoint - authenticates via IDP and creates Firefly session
     * 
     * @param request Username and password
     * @return Authentication response with IDP tokens and Firefly sessionId
     */
    @PostMapping("/login")
    public Mono<ResponseEntity<AuthenticationResponse>> login(@RequestBody LoginRequest request) {
        log.info("Login request for user: {}", request.getUsername());
        
        return authenticationService.login(request)
                .map(ResponseEntity::ok)
                .onErrorResume(AuthenticationServiceImpl.AuthenticationException.class,
                        error -> Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                                .build()))
                .onErrorResume(Exception.class,
                        error -> {
                            log.error("Unexpected error during login", error);
                            return Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                    .build());
                        });
    }

    /**
     * Logout endpoint - invalidates both IDP session and Firefly session
     * 
     * @param logoutRequest Access token, refresh token, and sessionId
     * @return 204 No Content on success
     */
    @PostMapping("/logout")
    public Mono<ResponseEntity<Void>> logout(@RequestBody AuthLogoutRequest logoutRequest) {
        log.info("Logout request for session: {}", logoutRequest.getSessionId());
        
        return authenticationService.logout(logoutRequest)
                .then(Mono.just(ResponseEntity.noContent().<Void>build()))
                .onErrorResume(error -> {
                    log.error("Error during logout", error);
                    return Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .<Void>build());
                });
    }

    /**
     * Refresh token endpoint - refreshes IDP tokens and updates session
     * 
     * @param request Refresh token
     * @return New authentication response with refreshed tokens
     */
    @PostMapping("/refresh")
    public Mono<ResponseEntity<AuthenticationResponse>> refresh(@RequestBody RefreshRequest request) {
        log.debug("Token refresh request");
        
        return authenticationService.refresh(request)
                .map(ResponseEntity::ok)
                .onErrorResume(AuthenticationServiceImpl.AuthenticationException.class,
                        error -> Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                                .build()))
                .onErrorResume(Exception.class,
                        error -> {
                            log.error("Unexpected error during token refresh", error);
                            return Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                    .build());
                        });
    }

    /**
     * Token introspection endpoint - validates IDP access token
     * 
     * @param accessToken The access token to introspect
     * @return Introspection response with token details
     */
    @PostMapping("/introspect")
    public Mono<ResponseEntity<IntrospectionResponse>> introspect(@RequestParam String accessToken) {
        log.debug("Token introspection request");
        
        return authenticationService.introspect(accessToken)
                .onErrorResume(error -> {
                    log.error("Error during token introspection", error);
                    return Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .build());
                });
    }

    /**
     * Reset password endpoint - triggers IDP password reset flow for a user
     *
     * @param userName Username to reset the password for
     * @return 204 No Content on success
     */
    @PostMapping("/reset-password")
    public Mono<ResponseEntity<Void>> resetPassword(@RequestParam String userName) {
        log.info("Reset password request for user: {}", userName);
        return authenticationService.resetPassword(userName)
                .then(Mono.just(ResponseEntity.noContent().<Void>build()))
                .onErrorResume(error -> {
                    log.error("Error during password reset", error);
                    return Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .<Void>build());
                });
    }
}
