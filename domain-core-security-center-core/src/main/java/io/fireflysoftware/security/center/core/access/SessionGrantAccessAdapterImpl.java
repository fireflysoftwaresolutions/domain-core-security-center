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

import io.fireflysoftware.security.center.interfaces.access.AccessDecision;
import io.fireflysoftware.security.center.interfaces.access.AccessRequest;
import io.fireflysoftware.security.center.interfaces.dtos.ContractInfoDTO;
import io.fireflysoftware.security.center.interfaces.dtos.RoleInfoDTO;
import io.fireflysoftware.security.center.interfaces.dtos.RoleScopeInfoDTO;
import io.fireflysoftware.security.center.interfaces.dtos.SessionContextDTO;
import io.fireflysoftware.security.center.session.AccessPort;
import io.fireflysoftware.security.center.session.FireflySessionManager;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Locale;
import java.util.UUID;

/**
 * Access adapter that evaluates role scopes already stored on the party session.
 * It does not call an identity provider. Select it with
 * {@code firefly.security-center.access.adapter=session-grants}.
 * A scope without {@code resourceId} covers every resource of that type.
 * A scope {@code resourceId} of {@code *} does the same.
 */
public final class SessionGrantAccessAdapterImpl implements AccessPort {

    private static final String ANY_RESOURCE = "*";

    private final FireflySessionManager sessionManager;

    public SessionGrantAccessAdapterImpl(FireflySessionManager sessionManager) {
        this.sessionManager = sessionManager;
    }

    @Override
    public Mono<AccessDecision> decide(AccessRequest request) {
        if (request == null
                || isBlank(request.getActorId())
                || request.getAction() == null
                || request.getResourceType() == null
                || isBlank(request.getResourceId())) {
            return Mono.just(AccessDecision.denied(AccessDecision.REQUEST_INCOMPLETE));
        }

        UUID partyId;
        try {
            partyId = UUID.fromString(request.getActorId().trim());
        } catch (IllegalArgumentException exception) {
            return Mono.just(AccessDecision.denied(AccessDecision.ACTOR_UNKNOWN));
        }

        return sessionManager.getSessionByPartyId(partyId)
                .map(session -> fromSession(session, request))
                .defaultIfEmpty(AccessDecision.denied(AccessDecision.ACTOR_UNKNOWN))
                .onErrorResume(error -> Mono.just(AccessDecision.denied(AccessDecision.SESSION_UNAVAILABLE)));
    }

    private AccessDecision fromSession(SessionContextDTO session, AccessRequest request) {
        if (session == null) {
            return AccessDecision.denied(AccessDecision.ACTOR_UNKNOWN);
        }
        if (session.getStatus() != null
                && session.getStatus() != SessionContextDTO.SessionStatus.ACTIVE) {
            return AccessDecision.denied(AccessDecision.ACTOR_NOT_ENTITLED);
        }

        List<RoleScopeInfoDTO> scopes = activeScopes(session);
        if (scopes.isEmpty()) {
            return AccessDecision.denied(AccessDecision.ACTOR_NOT_ENTITLED);
        }

        String resourceId = normalize(request.getResourceId());
        String action = request.getAction().name();
        String resourceType = request.getResourceType().name();
        boolean actionGranted = false;

        for (RoleScopeInfoDTO scope : scopes) {
            boolean actionMatches = action.equalsIgnoreCase(scope.getActionType());
            boolean typeMatches = resourceType.equalsIgnoreCase(scope.getResourceType());
            boolean resourceMatches = coversResource(scope.getResourceId(), resourceId);
            if (actionMatches && typeMatches && resourceMatches) {
                return AccessDecision.allowed(AccessDecision.SESSION_GRANT);
            }
            if (actionMatches) {
                actionGranted = true;
            }
        }
        if (!actionGranted) {
            return AccessDecision.denied(AccessDecision.ACTION_NOT_GRANTED);
        }
        return AccessDecision.denied(AccessDecision.RESOURCE_NOT_GRANTED);
    }

    private static List<RoleScopeInfoDTO> activeScopes(SessionContextDTO session) {
        if (session.getActiveContracts() == null) {
            return List.of();
        }
        return session.getActiveContracts().stream()
                .filter(contract -> Boolean.TRUE.equals(contract.getIsActive()))
                .map(ContractInfoDTO::getRoleInContract)
                .filter(role -> role != null && Boolean.TRUE.equals(role.getIsActive()))
                .map(RoleInfoDTO::getScopes)
                .filter(scopes -> scopes != null)
                .flatMap(List::stream)
                .filter(scope -> scope != null && Boolean.TRUE.equals(scope.getIsActive()))
                .toList();
    }

    private static boolean coversResource(String grantedResourceId, String requestedResourceId) {
        if (isBlank(grantedResourceId) || ANY_RESOURCE.equals(grantedResourceId.trim())) {
            return true;
        }
        return normalize(grantedResourceId).equals(requestedResourceId);
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private static String normalize(String value) {
        return value.trim().toLowerCase(Locale.ROOT);
    }
}
