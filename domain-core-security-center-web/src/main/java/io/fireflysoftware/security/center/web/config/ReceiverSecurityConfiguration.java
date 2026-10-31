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
import io.fireflysoftware.security.center.interfaces.identity.IdentityAdapter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.web.access.server.BearerTokenServerAccessDeniedHandler;
import org.springframework.security.oauth2.server.resource.web.server.BearerTokenServerAuthenticationEntryPoint;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.List;
import java.util.Set;

/** A bearer-only receiver; legacy credential proxies and administrative routes are unavailable. */
@Configuration
@EnableWebFluxSecurity
@EnableConfigurationProperties(ResourceServerProperties.class)
public class ReceiverSecurityConfiguration {
    @Bean
    public IdentityAdapter receiverIdentityAdapter(@Value("${firefly.security-center.identity.adapter}") String adapter) {
        return IdentityAdapter.fromProperty(adapter);
    }

    @Bean
    public SecurityWebFilterChain receiverSecurityWebFilterChain(ServerHttpSecurity http, ReactiveJwtDecoder decoder,
            Converter<Jwt, Mono<AbstractAuthenticationToken>> converter, ResourceServerProperties properties,
            Environment environment, @Value("${firefly.security-center.receiver.issuer}") String issuer,
            @Value("${firefly.security-center.receiver.audience}") String audience) {
        validate(properties, environment, issuer, audience);
        return http.securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .logout(ServerHttpSecurity.LogoutSpec::disable)
                .exceptionHandling(errors -> errors.authenticationEntryPoint(new BearerTokenServerAuthenticationEntryPoint())
                        .accessDeniedHandler(new BearerTokenServerAccessDeniedHandler()))
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/api/v1/access/checks", "/api/v1/identity/subjects", "/api/v1/sessions", "/api/v1/sessions/**").authenticated()
                        .anyExchange().denyAll())
                .oauth2ResourceServer(oauth -> oauth.jwt(jwt -> jwt.jwtDecoder(decoder).jwtAuthenticationConverter(converter)))
                .build();
    }

    static void validate(ResourceServerProperties properties, Environment environment, String issuer, String audience) {
        Set<String> asymmetric = Set.of("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512");
        if (issuer == null || issuer.isBlank() || audience == null || audience.isBlank()
                || !environment.getProperty("firefly.security.resource-server.enabled", Boolean.class, false)
                || !issuer.equals(properties.getIssuer()) || !List.of(audience).equals(properties.getAudiences())
                || properties.getJwkSetUri() == null || properties.getJwkSetUri().isBlank()
                || !properties.isTenantRequired() || !List.of("tenant_id").equals(properties.getTenantClaimPaths())
                || !properties.isStrictPolicy() || !properties.getPermitMatchers().isEmpty()
                || properties.getSignatureAlgorithms().isEmpty() || !asymmetric.containsAll(properties.getSignatureAlgorithms())) {
            throw new IllegalStateException("Explicit trusted receiver resource-server and strict policy configuration required");
        }
        String profile = environment.getProperty("firefly.security-center.receiver.transport-profile", "https");
        if (!Set.of("https", "isolated-firefly-id-sandbox").contains(profile)) {
            throw new IllegalStateException("Unknown receiver transport profile");
        }
        try {
            URI issuerUri = URI.create(issuer);
            URI jwksUri = URI.create(properties.getJwkSetUri());
            for (URI uri : List.of(issuerUri, jwksUri)) {
                if (!Set.of("https", "http").contains(uri.getScheme()) || uri.getHost() == null
                        || uri.getUserInfo() != null || uri.getFragment() != null || uri.getRawQuery() != null) {
                    throw new IllegalArgumentException();
                }
            }
            if (!"https".equals(issuerUri.getScheme()) || !"https".equals(jwksUri.getScheme())) {
                Set<String> localHosts = Set.of("id.firefly.test", "localhost", "127.0.0.1", "[::1]", "::1");
                Set<String> sandboxRealms = Set.of("/realms/sandbox-customers", "/realms/sandbox-workforce", "/realms/sandbox-institutions");
                if (!"isolated-firefly-id-sandbox".equals(profile)
                        || !"http".equals(issuerUri.getScheme()) || !"http".equals(jwksUri.getScheme())
                        || !localHosts.contains(issuerUri.getHost()) || issuerUri.getPort() != 8180
                        || !sandboxRealms.contains(issuerUri.getRawPath())
                        || !(issuer + "/protocol/openid-connect/certs").equals(properties.getJwkSetUri())) {
                    throw new IllegalArgumentException();
                }
            }
        } catch (IllegalArgumentException error) {
            throw new IllegalStateException("HTTPS issuer/JWKS required; HTTP is restricted to the exact isolated Firefly ID sandbox profile");
        }
    }
}
