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

import io.fireflysoftware.security.center.interfaces.identity.IdentityAdapter;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.Ordered;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

import java.util.HashMap;
import java.util.Map;

/**
 * Copies {@code firefly.security-center.identity.adapter} onto the provider
 * properties Jafly and this service already read. Sandbox does not select a
 * Jafly provider, so no identity-provider process starts.
 */
public class IdentityAdapterEnvironmentPostProcessorImpl implements EnvironmentPostProcessor, Ordered {

    static final String ADAPTER = "firefly.security-center.identity.adapter";

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        IdentityAdapter adapter = IdentityAdapter.fromProperty(environment.getProperty(ADAPTER, "sandbox"));
        String token = adapter.propertyValue();
        Map<String, Object> values = new HashMap<>();
        values.put("firefly.security-center.idp.provider", token);
        if (adapter != IdentityAdapter.SANDBOX) {
            values.put("firefly.security.idp.provider", token);
        }
        environment.getPropertySources().addFirst(new MapPropertySource("firefly-identity-adapter", values));
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }
}
