/*
 * Copyright 2026 Firefly Software Foundation
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy at https://www.apache.org/licenses/LICENSE-2.0
 * Distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND.
 */
package io.fireflysoftware.security.center.web.openapi;

import org.junit.jupiter.api.Test;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import static org.junit.jupiter.api.Assertions.*;
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

    @Test
    void originalProducerPreservesAllVisibleBearerRequirementsAndStableConsumerOperations() throws IOException {
        byte[] body = WebTestClient.bindToServer().baseUrl("http://127.0.0.1:" + port).build()
                .get().uri("/v3/api-docs").exchange().expectStatus().isOk().expectBody().returnResult()
                .getResponseBody();
        assertNotNull(body);
        Path output = Path.of("target", "receiver-openapi.json");
        Files.createDirectories(output.getParent());
        Files.write(output, body);
        JsonNode document = new ObjectMapper().readTree(body);
        Map<String, String> consumers = Map.of("/api/v1/access/checks", "decideAccess",
                "/api/v1/identity/subjects", "resolveSubject");
        assertEquals("resolveSubject", document.path("paths").path("/api/v1/identity/subjects")
                .path("post").path("operationId").asText());
        consumers.forEach((path, operation) -> {
            JsonNode metadata = document.path("paths").path(path).path("post");
            assertEquals(operation, metadata.path("operationId").asText());
            String responseType = path.equals("/api/v1/identity/subjects") ? "Subject" : "AccessDecision";
            assertEquals("#/components/schemas/" + responseType, metadata.path("responses").path("200")
                    .path("content").path("application/json").path("schema").path("$ref").asText());
            int retryKeys = 0;
            for (JsonNode parameter : metadata.path("parameters")) {
                if ("X-Idempotency-Key".equals(parameter.path("name").asText())) {
                    retryKeys++;
                    assertEquals("header", parameter.path("in").asText());
                    assertFalse(parameter.path("required").asBoolean());
                    assertEquals("string", parameter.path("schema").path("type").asText());
                }
            }
            assertEquals(1, retryKeys);
        });
        int operations = 0;
        for (JsonNode path : document.path("paths")) {
            for (String method : List.of("get", "post", "put", "patch", "delete", "head", "options", "trace")) {
                JsonNode operation = path.get(method);
                if (operation == null) continue;
                operations++;
                JsonNode requirements = operation.path("security");
                assertTrue(requirements.isArray() && requirements.size() == 1,
                        "Every visible operation must require exactly the receiver bearer scheme");
                JsonNode requirement = requirements.get(0);
                assertEquals(1, requirement.size());
                assertTrue(requirement.path("bearerAuth").isArray());
                assertEquals(0, requirement.path("bearerAuth").size());
                assertTrue(operation.path("responses").has("401"));
                assertTrue(operation.path("responses").has("403"));
            }
        }
        assertTrue(operations >= 3);
        for (String hidden : List.of("/api/v1/auth/login", "/api/v1/auth/refresh", "/api/v1/auth/logout",
                "/api/v1/auth/reset-password", "/api/v1/auth/introspect", "/api/v1/users")) {
            assertFalse(document.path("paths").has(hidden));
        }
    }

}
