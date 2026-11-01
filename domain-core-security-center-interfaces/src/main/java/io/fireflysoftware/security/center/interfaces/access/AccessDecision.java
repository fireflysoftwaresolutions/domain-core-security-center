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

package io.fireflysoftware.security.center.interfaces.access;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * AccessPort response. {@code allowed} is true when the actor may perform the
 * action, and false when the actor is denied. {@code reasonCode} says why.
 *
 * <pre>
 * { "allowed": true,  "reasonCode": "SANDBOX_GRANT" }
 * { "allowed": false, "reasonCode": "ACTOR_NOT_ENTITLED" }
 * </pre>
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AccessDecision {

    /** Current verified caller policy permitted the exact operation and resource. */
    public static final String CURRENT_POLICY_PERMIT = "CURRENT_POLICY_PERMIT";

    /** The sandbox policy granted this actor the action on this resource. */
    public static final String SANDBOX_GRANT = "SANDBOX_GRANT";

    /** The actor is listed and has no grant for the request. */
    public static final String ACTOR_NOT_ENTITLED = "ACTOR_NOT_ENTITLED";

    /** The actor is not listed in the policy, or the session has no such party. */
    public static final String ACTOR_UNKNOWN = "ACTOR_UNKNOWN";

    /** The actor has grants, and none of them include this action. */
    public static final String ACTION_NOT_GRANTED = "ACTION_NOT_GRANTED";

    /** The actor has the action, and none of those grants cover this resource. */
    public static final String RESOURCE_NOT_GRANTED = "RESOURCE_NOT_GRANTED";

    /** The request is missing the actor, the action, the resource type, or the resource id. */
    public static final String REQUEST_INCOMPLETE = "REQUEST_INCOMPLETE";

    /** A role scope on the party session granted the action. */
    public static final String SESSION_GRANT = "SESSION_GRANT";

    /** The session grant adapter could not read the party session. */
    public static final String SESSION_UNAVAILABLE = "SESSION_UNAVAILABLE";

    /** A realm role from the identity provider granted this action. */
    public static final String REALM_ROLE_GRANT = "REALM_ROLE_GRANT";

    @JsonProperty("allowed")
    private boolean allowed;

    @JsonProperty("reasonCode")
    private String reasonCode;

    public static AccessDecision allowed(String reasonCode) {
        return AccessDecision.builder().allowed(true).reasonCode(reasonCode).build();
    }

    public static AccessDecision denied(String reasonCode) {
        return AccessDecision.builder().allowed(false).reasonCode(reasonCode).build();
    }
}
