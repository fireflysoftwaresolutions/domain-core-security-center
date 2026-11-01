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

import io.fireflysoftware.security.center.core.access.SandboxPolicyAccessAdapterImpl;
import io.fireflysoftware.security.center.core.authorization.CurrentPolicyAccessAdapter;
import io.fireflysoftware.security.center.core.authorization.AdmittedAccessRestriction;
import io.fireflysoftware.security.center.core.authorization.ReceiverAuthorization;
import io.fireflysoftware.security.center.core.access.SessionGrantAccessAdapterImpl;
import io.fireflysoftware.security.center.core.access.SubjectBoundAccessAdapterImpl;
import io.fireflysoftware.security.center.session.AccessPort;
import io.fireflysoftware.security.center.session.FireflySessionManager;
import io.fireflysoftware.security.center.session.IdentityPort;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ResourceLoader;

/**
 * Selects current verified-caller policy admission by default.
 * Explicit legacy adapters remain available only as additional restrictions behind receiver admission.
 * {@code firefly.security-center.access.adapter=session-grants} uses role
 * scopes on the party session instead. Another bean of type {@link AccessPort}
 * can replace either adapter when a deployment calls an entitlement store.
 */
@Configuration
public class AccessPortConfiguration {

    @Bean
    @ConditionalOnProperty(prefix = "firefly.security-center.access", name = "adapter", havingValue = "current-policy", matchIfMissing = true)
    public AccessPort currentPolicyAccessPort(ReceiverAuthorization authorization) {
        return new CurrentPolicyAccessAdapter(authorization);
    }

    @Bean
    @ConditionalOnProperty(prefix = "firefly.security-center.access", name = "adapter", havingValue = "session-grants")
    public AccessPort sessionGrantAccessPort(IdentityPort identityPort, FireflySessionManager sessionManager, ReceiverAuthorization authorization) {
        return new AdmittedAccessRestriction(authorization,
                new SubjectBoundAccessAdapterImpl(identityPort, new SessionGrantAccessAdapterImpl(sessionManager)));
    }

    @Bean
    @ConditionalOnProperty(
            prefix = "firefly.security-center.access",
            name = "adapter",
            havingValue = "sandbox",
            matchIfMissing = false)
    public AccessPort sandboxAccessPort(
            IdentityPort identityPort,
            ResourceLoader resourceLoader,
            @Value("${firefly.security-center.access.sandbox-policy:" + SandboxPolicyAccessAdapterImpl.DEFAULT_LOCATION + "}")
            String location, ReceiverAuthorization authorization) {
        return new AdmittedAccessRestriction(authorization,
                new SubjectBoundAccessAdapterImpl(identityPort, new SandboxPolicyAccessAdapterImpl(resourceLoader, location)));
    }
}
