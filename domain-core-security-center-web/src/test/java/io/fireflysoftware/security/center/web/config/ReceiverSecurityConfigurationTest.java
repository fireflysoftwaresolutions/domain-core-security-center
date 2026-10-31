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

package io.fireflysoftware.security.center.web.config;

import org.fireflyframework.security.rs.ResourceServerProperties;
import org.fireflyframework.security.rs.ResourceServerAutoConfiguration;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.server.WebFilterChainProxy;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;
import reactor.core.publisher.Mono;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicInteger;
import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ReceiverSecurityConfigurationTest {
    private ResourceServerProperties configured() {
        ResourceServerProperties properties = new ResourceServerProperties();
        properties.setIssuer("https://identity.example/realms/customers");
        properties.setJwkSetUri("https://identity.example/realms/customers/protocol/openid-connect/certs");
        properties.setAudiences(List.of("security-center"));
        properties.setTenantClaimPaths(List.of("tenant_id"));
        properties.setTenantRequired(true);
        properties.setStrictPolicy(true);
        return properties;
    }

    @Test
    void missingTrustOrDisabledDecoderOrNonStrictPolicyCannotStartReceiver() {
        ResourceServerProperties missingJwks = configured();
        var environment = new MockEnvironment().withProperty("firefly.security.resource-server.enabled", "true");
        ReceiverSecurityConfiguration.validate(missingJwks, environment, missingJwks.getIssuer(), "security-center");
        missingJwks.setJwkSetUri(null);
        assertThatThrownBy(() -> ReceiverSecurityConfiguration.validate(missingJwks, environment, missingJwks.getIssuer(), "security-center"))
                .isInstanceOf(IllegalStateException.class);
        ResourceServerProperties nonStrict = configured();
        nonStrict.setStrictPolicy(false);
        assertThatThrownBy(() -> ReceiverSecurityConfiguration.validate(nonStrict, environment, nonStrict.getIssuer(), "security-center"))
                .isInstanceOf(IllegalStateException.class);
        ResourceServerProperties valid = configured();
        assertThatThrownBy(() -> ReceiverSecurityConfiguration.validate(valid, new MockEnvironment(), valid.getIssuer(), "security-center"))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void differentIssuerAudienceTenantProjectionAndSymmetricAlgorithmsCannotStartReceiver() {
        for (String invalid : List.of("issuer", "audience", "tenant", "algorithm")) {
            ResourceServerProperties properties = configured();
            switch (invalid) {
                case "issuer" -> properties.setIssuer("https://another.example");
                case "audience" -> properties.setAudiences(List.of("another-service"));
                case "tenant" -> properties.setTenantRequired(false);
                case "algorithm" -> properties.setSignatureAlgorithms(List.of("HS256"));
            }
            assertThatThrownBy(() -> ReceiverSecurityConfiguration.validate(properties,
                    new MockEnvironment().withProperty("firefly.security.resource-server.enabled", "true"),
                    "https://identity.example/realms/customers", "security-center")).isInstanceOf(IllegalStateException.class);
        }
    }
    @Test
    void remoteHttpIssuerOrJwksCannotStartEvenWithTheIsolatedProfile() {
        ResourceServerProperties secure = configured();
        assertThatThrownBy(() -> ReceiverSecurityConfiguration.validate(secure,
                new MockEnvironment().withProperty("firefly.security.resource-server.enabled", "true")
                        .withProperty("firefly.security-center.receiver.transport-profile", "disabled"),
                secure.getIssuer(), "security-center")).isInstanceOf(IllegalStateException.class);
        for (String host : List.of("identity.example", "attacker.invalid", "id.firefly.test.attacker.invalid", "10.0.0.1")) {
            ResourceServerProperties properties = configured();
            String issuer = "http://" + host + ":8180/realms/sandbox-customers";
            properties.setIssuer(issuer);
            properties.setJwkSetUri(issuer + "/protocol/openid-connect/certs");
            for (String profile : List.of("https", "isolated-firefly-id-sandbox")) {
                var environment = new MockEnvironment().withProperty("firefly.security.resource-server.enabled", "true")
                        .withProperty("firefly.security-center.receiver.transport-profile", profile);
                assertThatThrownBy(() -> ReceiverSecurityConfiguration.validate(properties, environment, issuer, "security-center"))
                        .isInstanceOf(IllegalStateException.class);
            }
        }
        ResourceServerProperties mixed = configured();
        mixed.setJwkSetUri("http://attacker.invalid:8180/realms/sandbox-customers/protocol/openid-connect/certs");
        assertThatThrownBy(() -> ReceiverSecurityConfiguration.validate(mixed,
                new MockEnvironment().withProperty("firefly.security.resource-server.enabled", "true")
                        .withProperty("firefly.security-center.receiver.transport-profile", "isolated-firefly-id-sandbox"),
                mixed.getIssuer(), "security-center")).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void httpNeedsExactIsolatedProfileCanonicalSandboxOriginRealmPortAndJwksPath() {
        for (String host : List.of("id.firefly.test", "localhost", "127.0.0.1", "[::1]")) {
            ResourceServerProperties properties = configured();
            String issuer = "http://" + host + ":8180/realms/sandbox-customers";
            properties.setIssuer(issuer);
            properties.setJwkSetUri(issuer + "/protocol/openid-connect/certs");
            var environment = new MockEnvironment().withProperty("firefly.security.resource-server.enabled", "true");
            assertThatThrownBy(() -> ReceiverSecurityConfiguration.validate(properties, environment, issuer, "security-center"))
                    .isInstanceOf(IllegalStateException.class);
            environment.withProperty("firefly.security-center.receiver.transport-profile", "isolated-firefly-id-sandbox");
            ReceiverSecurityConfiguration.validate(properties, environment, issuer, "security-center");
            properties.setJwkSetUri(issuer + "/not-the-jwks-endpoint");
            assertThatThrownBy(() -> ReceiverSecurityConfiguration.validate(properties, environment, issuer, "security-center"))
                    .isInstanceOf(IllegalStateException.class);
        }
        for (String issuer : List.of("http://id.firefly.test:8080/realms/sandbox-customers",
                "http://id.firefly.test:8180/realms/production", "http://id.firefly.test:8180/realms/sandbox-customers?override=true")) {
            ResourceServerProperties properties = configured();
            properties.setIssuer(issuer);
            properties.setJwkSetUri(issuer + "/protocol/openid-connect/certs");
            assertThatThrownBy(() -> ReceiverSecurityConfiguration.validate(properties,
                    new MockEnvironment().withProperty("firefly.security.resource-server.enabled", "true")
                            .withProperty("firefly.security-center.receiver.transport-profile", "isolated-firefly-id-sandbox"),
                    issuer, "security-center")).isInstanceOf(IllegalStateException.class);
        }
    }

    @Test
    void legacyCredentialProvisioningAdminAndManagementRoutesRemainUnavailableEvenWithBearer() {
        ResourceServerProperties properties = configured();
        var jwt = Jwt.withTokenValue("non-secret-test-token").header("alg", "RS256")
                .issuer(properties.getIssuer()).subject("opaque-subject").audience(List.of("security-center"))
                .expiresAt(Instant.now().plusSeconds(300)).claim("tenant_id", "opaque-tenant")
                .claim("principal_kind", "HUMAN").claim("party_id", "11111111-1111-4111-8111-111111111111").build();
        var framework = new ResourceServerAutoConfiguration();
        var converter = framework.fireflyJwtAuthenticationConverter(
                framework.fireflyPrincipalFactory(framework.fireflyAuthorityMappingPort(properties)), properties);
        var chain = new ReceiverSecurityConfiguration().receiverSecurityWebFilterChain(ServerHttpSecurity.http(),
                compact -> Mono.just(jwt), converter, properties,
                new MockEnvironment().withProperty("firefly.security.resource-server.enabled", "true"),
                properties.getIssuer(), "security-center");
        var probe = new LegacyProbe();
        var client = WebTestClient.bindToController(probe).webFilter(new WebFilterChainProxy(chain)).build();
        for (String route : List.of("/api/v1/auth/login", "/api/v1/auth/refresh", "/api/v1/users", "/idp/admin/users", "/actuator/health")) {
            client.post().uri(route).exchange().expectStatus().isUnauthorized();
            client.post().uri(route).header("Authorization", "Bearer non-secret-test-token")
                    .exchange().expectStatus().isForbidden();
        }
        assertThat(probe.calls).hasValue(0);
    }

    @RestController
    static class LegacyProbe {
        final AtomicInteger calls = new AtomicInteger();
        @RequestMapping({"/api/v1/auth/login", "/api/v1/auth/refresh", "/api/v1/users", "/idp/admin/users", "/actuator/health"})
        String receive() { calls.incrementAndGet(); return "unavailable"; }
    }

}
