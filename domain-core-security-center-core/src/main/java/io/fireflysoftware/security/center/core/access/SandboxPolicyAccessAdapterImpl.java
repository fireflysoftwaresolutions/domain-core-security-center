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

package io.fireflysoftware.security.center.core.access;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.fireflysoftware.security.center.interfaces.access.AccessAction;
import io.fireflysoftware.security.center.interfaces.access.AccessDecision;
import io.fireflysoftware.security.center.interfaces.access.AccessRequest;
import io.fireflysoftware.security.center.interfaces.access.AccessResourceType;
import io.fireflysoftware.security.center.session.AccessPort;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Access adapter that decides from a policy file. It does not call an identity
 * provider and it does not embed allow or deny rules for particular actors.
 * An installer replaces the policy file, then restarts the service.
 */
public final class SandboxPolicyAccessAdapterImpl implements AccessPort {

    /**
     * Classpath location of the policy shipped with this service.
     * Source file: {@code domain-core-security-center-core/src/main/resources/access/sandbox-access-policy.json}.
     */
    public static final String DEFAULT_LOCATION = "classpath:access/sandbox-access-policy.json";

    private static final String ANY_RESOURCE = "*";

    private final Map<String, List<Grant>> grantsByActor;
    private final Map<String, List<Grant>> grantsByRole;

    public SandboxPolicyAccessAdapterImpl(ResourceLoader resourceLoader, String location) {
        LoadedPolicy loaded = load(resourceLoader, location);
        this.grantsByActor = loaded.grantsByActor();
        this.grantsByRole = loaded.grantsByRole();
    }

    @Override
    public Mono<AccessDecision> decide(AccessRequest request) {
        return decide(request, List.of());
    }

    /**
     * Decides from actor grants, then from realm roles supplied by IdentityPort.
     * A matching realm role allows the action even when the actor is not listed.
     */
    public Mono<AccessDecision> decide(AccessRequest request, List<String> realmRoles) {
        return Mono.fromSupplier(() -> {
            AccessDecision actorDecision = decideNow(request);
            if (actorDecision.isAllowed() || realmRoles == null || realmRoles.isEmpty()) {
                return actorDecision;
            }
            AccessDecision roleDecision = decideByRole(request, realmRoles);
            return roleDecision == null ? actorDecision : roleDecision;
        });
    }

    private AccessDecision decideByRole(AccessRequest request, List<String> realmRoles) {
        if (request == null || request.getAction() == null || request.getResourceType() == null || isBlank(request.getResourceId())) {
            return null;
        }
        for (String role : realmRoles) {
            if (isBlank(role)) {
                continue;
            }
            List<Grant> grants = grantsByRole.get(normalize(role));
            if (grants == null) {
                continue;
            }
            if (matches(grants, request)) {
                return AccessDecision.allowed(AccessDecision.REALM_ROLE_GRANT);
            }
        }
        return null;
    }

    private AccessDecision decideNow(AccessRequest request) {
        if (request == null
                || isBlank(request.getActorId())
                || request.getAction() == null
                || request.getResourceType() == null
                || isBlank(request.getResourceId())) {
            return AccessDecision.denied(AccessDecision.REQUEST_INCOMPLETE);
        }

        List<Grant> grants = grantsByActor.get(normalize(request.getActorId()));
        if (grants == null) {
            return AccessDecision.denied(AccessDecision.ACTOR_UNKNOWN);
        }
        if (grants.isEmpty()) {
            return AccessDecision.denied(AccessDecision.ACTOR_NOT_ENTITLED);
        }

        if (matches(grants, request)) {
            return AccessDecision.allowed(AccessDecision.SANDBOX_GRANT);
        }
        boolean actionGranted = grants.stream().anyMatch(grant -> grant.action == request.getAction());
        if (!actionGranted) {
            return AccessDecision.denied(AccessDecision.ACTION_NOT_GRANTED);
        }
        return AccessDecision.denied(AccessDecision.RESOURCE_NOT_GRANTED);
    }

    private static boolean matches(List<Grant> grants, AccessRequest request) {
        String resourceId = normalize(request.getResourceId());
        for (Grant grant : grants) {
            boolean actionMatches = grant.action == request.getAction();
            boolean typeMatches = grant.resourceType == request.getResourceType();
            boolean resourceMatches = ANY_RESOURCE.equals(grant.resourceId)
                    || normalize(grant.resourceId).equals(resourceId);
            if (actionMatches && typeMatches && resourceMatches) {
                return true;
            }
        }
        return false;
    }

    private static LoadedPolicy load(ResourceLoader resourceLoader, String location) {
        if (isBlank(location)) {
            throw new IllegalStateException("Sandbox access policy location is required");
        }
        Resource resource = resourceLoader.getResource(location);
        if (!resource.exists()) {
            throw new IllegalStateException("Sandbox access policy not found: " + location);
        }
        PolicyFile policy = read(resource, location);
        if (policy.actors == null) {
            throw new IllegalStateException("Sandbox access policy must contain an actors array: " + location);
        }

        Map<String, List<Grant>> grantsByActor = new LinkedHashMap<>();
        for (ActorEntry actor : policy.actors) {
            if (actor == null || isBlank(actor.actorId)) {
                throw new IllegalStateException("Sandbox access policy actor is missing an actorId: " + location);
            }
            List<Grant> grants = grantsByActor.computeIfAbsent(normalize(actor.actorId), key -> new ArrayList<>());
            grants.addAll(readGrants(actor.grants, location));
        }

        Map<String, List<Grant>> grantsByRole = new LinkedHashMap<>();
        if (policy.roles != null) {
            for (RoleEntry role : policy.roles) {
                if (role == null || isBlank(role.role)) {
                    throw new IllegalStateException("Sandbox access policy role is missing a name: " + location);
                }
                List<Grant> grants = grantsByRole.computeIfAbsent(normalize(role.role), key -> new ArrayList<>());
                grants.addAll(readGrants(role.grants, location));
            }
        }
        return new LoadedPolicy(Map.copyOf(grantsByActor), Map.copyOf(grantsByRole));
    }

    private static List<Grant> readGrants(List<GrantEntry> entries, String location) {
        if (entries == null) {
            return List.of();
        }
        List<Grant> grants = new ArrayList<>();
        for (GrantEntry entry : entries) {
            if (entry == null || entry.action == null || entry.resourceType == null || isBlank(entry.resourceId)) {
                throw new IllegalStateException("Sandbox access policy grant is incomplete: " + location);
            }
            grants.add(new Grant(entry.action, entry.resourceType, entry.resourceId.trim()));
        }
        return grants;
    }

    private static PolicyFile read(Resource resource, String location) {
        ObjectMapper mapper = new ObjectMapper()
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        try (InputStream input = resource.getInputStream()) {
            PolicyFile policy = mapper.readValue(input, PolicyFile.class);
            if (policy == null) {
                throw new IllegalStateException("Sandbox access policy is empty: " + location);
            }
            return policy;
        } catch (IOException exception) {
            throw new IllegalStateException("Sandbox access policy could not be read: " + location, exception);
        }
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private static String normalize(String value) {
        return value.trim().toLowerCase(Locale.ROOT);
    }

    private record Grant(AccessAction action, AccessResourceType resourceType, String resourceId) {
    }

    private record LoadedPolicy(Map<String, List<Grant>> grantsByActor, Map<String, List<Grant>> grantsByRole) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private static final class PolicyFile {
        public List<ActorEntry> actors;
        public List<RoleEntry> roles;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private static final class RoleEntry {
        public String role;
        public List<GrantEntry> grants;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private static final class ActorEntry {
        public String actorId;
        public List<GrantEntry> grants;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private static final class GrantEntry {
        public AccessAction action;
        public AccessResourceType resourceType;
        public String resourceId;
    }
}
