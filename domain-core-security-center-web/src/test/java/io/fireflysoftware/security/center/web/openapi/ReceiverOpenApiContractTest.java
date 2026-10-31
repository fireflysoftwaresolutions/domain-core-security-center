/*
 * Copyright 2026 Firefly Software Foundation
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy at https://www.apache.org/licenses/LICENSE-2.0
 * Distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND.
 */
package io.fireflysoftware.security.center.web.openapi;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.test.context.ActiveProfiles;

/** Exercises the actual producer generation harness, not the production receiver security chain. */
@ActiveProfiles("openapi-gen")
@SpringBootTest(classes = OpenApiGenApplication.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"spring.config.name=openapi-contract-fixture", "spring.main.web-application-type=reactive",
                "server.address=127.0.0.1", "springdoc.api-docs.enabled=true", "springdoc.paths-to-match=/api/**"})
class ReceiverOpenApiContractTest {
    @Value("${local.server.port}")
    private int port;

    @Test
    void generatedReceiverContractDeclaresBearerAuthAndExcludesUnavailableCredentialOperations() {
        WebTestClient.bindToServer().baseUrl("http://127.0.0.1:" + port).build()
                .get().uri("/v3/api-docs").exchange().expectStatus().isOk().expectBody()
                .jsonPath("$.components.securitySchemes.bearerAuth.type").isEqualTo("http")
                .jsonPath("$.components.securitySchemes.bearerAuth.scheme").isEqualTo("bearer")
                .jsonPath("$.components.securitySchemes.bearerAuth.bearerFormat").isEqualTo("JWT")
                .jsonPath("$.paths['/api/v1/access/checks'].post.security[0].bearerAuth").isArray()
                .jsonPath("$.paths['/api/v1/identity/subjects'].post.security[0].bearerAuth").isArray()
                .jsonPath("$.paths['/api/v1/sessions'].post.security[0].bearerAuth").isArray()
                .jsonPath("$.paths['/api/v1/access/checks'].post.responses['401']").exists()
                .jsonPath("$.paths['/api/v1/access/checks'].post.responses['403']").exists()
                .jsonPath("$.paths['/api/v1/auth/login']").doesNotExist()
                .jsonPath("$.paths['/api/v1/auth/refresh']").doesNotExist()
                .jsonPath("$.paths['/api/v1/auth/introspect']").doesNotExist()
                .jsonPath("$.paths['/api/v1/users']").doesNotExist();
    }
}
