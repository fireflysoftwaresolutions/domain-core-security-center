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

package io.fireflysoftware.security.center.core.config;

import io.fireflysoftware.security.center.core.identity.JaflyIdentityAdapterImpl;
import io.fireflysoftware.security.center.core.identity.SandboxIdentityAdapterImpl;
import io.fireflysoftware.security.center.interfaces.identity.IdentityAdapter;
import io.fireflysoftware.security.center.session.IdentityPort;
import org.fireflyframework.security.idp.adapter.IdpAdapter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Selects who resolves the actor. {@code firefly.security-center.identity.adapter}
 * is {@code sandbox} (default), {@code keycloak}, {@code cognito}, or {@code internal-db}.
 * Keycloak, Cognito, and the internal database use the matching Jafly {@link IdpAdapter}.
 * Set the same value on {@code firefly.security.idp.provider} so Jafly activates that adapter.
 */
@Configuration
public class IdentityPortConfiguration {

    @Bean
    @ConditionalOnProperty(
            prefix = "firefly.security-center.identity",
            name = "adapter",
            havingValue = "sandbox",
            matchIfMissing = true)
    public IdentityPort sandboxIdentityPort() {
        return new SandboxIdentityAdapterImpl();
    }

    @Bean
    @ConditionalOnExpression("'${firefly.security-center.identity.adapter:sandbox}' == 'keycloak' or '${firefly.security-center.identity.adapter:sandbox}' == 'cognito' or '${firefly.security-center.identity.adapter:sandbox}' == 'internal-db'")
    public IdentityPort jaflyIdentityPort(
            IdpAdapter idpAdapter,
            @Value("${firefly.security-center.identity.adapter}") String adapter) {
        return new JaflyIdentityAdapterImpl(idpAdapter, IdentityAdapter.fromProperty(adapter));
    }
}
