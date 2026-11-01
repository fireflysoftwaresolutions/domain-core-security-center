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

package io.fireflysoftware.security.center.web.config;

import io.fireflysoftware.core.customer.sdk.api.EmailContactsApi;
import io.fireflysoftware.core.customer.sdk.api.PartiesApi;
import io.fireflysoftware.security.center.core.services.DefaultUserMappingServiceImpl;
import io.fireflysoftware.security.center.core.services.UserMappingService;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

/**
 * Test configuration for Security Center integration tests.
 *
 * <p>This configuration ensures that {@link DefaultUserMappingServiceImpl} is created
 * in the test context using the mocked SDK APIs.
 */
@TestConfiguration
public class SecurityCenterTestConfiguration {

    /**
     * Create DefaultUserMappingServiceImpl bean for tests.
     * This bean will use the mocked PartiesApi and EmailContactsApi from the test context.
     */
    @Bean
    @Primary
    public UserMappingService userMappingService(PartiesApi partiesApi, EmailContactsApi emailContactsApi) {
        return new DefaultUserMappingServiceImpl(partiesApi, emailContactsApi);
    }
}

