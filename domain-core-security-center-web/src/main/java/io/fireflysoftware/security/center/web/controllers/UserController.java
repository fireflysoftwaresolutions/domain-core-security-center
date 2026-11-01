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

import org.fireflyframework.security.idp.dtos.CreateUserRequest;
import org.fireflyframework.security.idp.dtos.CreateUserResponse;
import io.fireflysoftware.security.center.core.services.UserServiceImpl;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/**
 * REST controller for user management operations.
 */
@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
@Slf4j
public class UserController {

    private final UserServiceImpl userService;

    /**
     * Handles the creation of a new user.
     *
     * @param request the details of the user to be created, encapsulated in a {@link CreateUserRequest} object
     * @return a {@link Mono} wrapping a {@link ResponseEntity} object containing the {@link CreateUserResponse},
     *         or an internal server error response in case of an error
     */
    @PostMapping
    public Mono<ResponseEntity<CreateUserResponse>> createUser(@RequestBody CreateUserRequest request) {
        log.info("Received create user request");
        return userService.createUser(request)
                .onErrorResume(ex -> {
                    log.error("Error creating user", ex);
                    return Mono.just(ResponseEntity.internalServerError().build());
                });
    }
}
