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

import io.fireflysoftware.security.center.interfaces.access.AccessAction;
import io.fireflysoftware.security.center.interfaces.access.AccessDecision;
import io.fireflysoftware.security.center.interfaces.access.AccessRequest;
import io.fireflysoftware.security.center.interfaces.access.AccessResourceType;
import io.fireflysoftware.security.center.interfaces.dtos.ContractInfoDTO;
import io.fireflysoftware.security.center.interfaces.dtos.RoleInfoDTO;
import io.fireflysoftware.security.center.interfaces.dtos.RoleScopeInfoDTO;
import io.fireflysoftware.security.center.interfaces.dtos.SessionContextDTO;
import io.fireflysoftware.security.center.session.FireflySessionManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SessionGrantAccessAdapterTest {

    private static final UUID ACTOR_ID = UUID.fromString("11111111-1111-4111-8111-111111111111");
    private static final String ACCOUNT_ID = "10000000-0000-4000-8000-000000000002";

    @Mock
    private FireflySessionManager sessionManager;

    @Test
    void activeScopeWithMatchingResourceAllows() {
        when(sessionManager.getSessionByPartyId(ACTOR_ID)).thenReturn(Mono.just(session(scope("READ", "ACCOUNT", ACCOUNT_ID))));

        assertDecision(request(ACTOR_ID.toString(), AccessAction.READ, AccessResourceType.ACCOUNT, ACCOUNT_ID),
                true, AccessDecision.SESSION_GRANT);
    }

    @Test
    void scopeWithoutResourceIdCoversEveryResourceOfThatType() {
        when(sessionManager.getSessionByPartyId(ACTOR_ID)).thenReturn(Mono.just(session(scope("CREATE", "CARD", null))));

        assertDecision(request(ACTOR_ID.toString(), AccessAction.CREATE, AccessResourceType.CARD, "new-card"),
                true, AccessDecision.SESSION_GRANT);
    }

    @Test
    void scopeForADifferentResourceDenies() {
        when(sessionManager.getSessionByPartyId(ACTOR_ID)).thenReturn(Mono.just(session(scope("READ", "ACCOUNT", ACCOUNT_ID))));

        assertDecision(request(ACTOR_ID.toString(), AccessAction.READ, AccessResourceType.ACCOUNT, "other-account"),
                false, AccessDecision.RESOURCE_NOT_GRANTED);
    }

    @Test
    void scopeForADifferentActionDenies() {
        when(sessionManager.getSessionByPartyId(ACTOR_ID)).thenReturn(Mono.just(session(scope("READ", "ACCOUNT", ACCOUNT_ID))));

        assertDecision(request(ACTOR_ID.toString(), AccessAction.UPDATE, AccessResourceType.ACCOUNT, ACCOUNT_ID),
                false, AccessDecision.ACTION_NOT_GRANTED);
    }

    @Test
    void inactiveScopeDoesNotGrant() {
        RoleScopeInfoDTO scope = scope("READ", "ACCOUNT", ACCOUNT_ID);
        scope.setIsActive(false);
        when(sessionManager.getSessionByPartyId(ACTOR_ID)).thenReturn(Mono.just(session(scope)));

        assertDecision(request(ACTOR_ID.toString(), AccessAction.READ, AccessResourceType.ACCOUNT, ACCOUNT_ID),
                false, AccessDecision.ACTOR_NOT_ENTITLED);
    }

    @Test
    void expiredSessionDenies() {
        SessionContextDTO session = session(scope("READ", "ACCOUNT", ACCOUNT_ID));
        session.setStatus(SessionContextDTO.SessionStatus.EXPIRED);
        when(sessionManager.getSessionByPartyId(ACTOR_ID)).thenReturn(Mono.just(session));

        assertDecision(request(ACTOR_ID.toString(), AccessAction.READ, AccessResourceType.ACCOUNT, ACCOUNT_ID),
                false, AccessDecision.ACTOR_NOT_ENTITLED);
    }

    @Test
    void missingSessionDeniesTheActorAsUnknown() {
        when(sessionManager.getSessionByPartyId(ACTOR_ID)).thenReturn(Mono.empty());

        assertDecision(request(ACTOR_ID.toString(), AccessAction.READ, AccessResourceType.ACCOUNT, ACCOUNT_ID),
                false, AccessDecision.ACTOR_UNKNOWN);
    }

    @Test
    void sessionLookupFailureDeniesWithoutCallingAnIdentityProvider() {
        when(sessionManager.getSessionByPartyId(ACTOR_ID)).thenReturn(Mono.error(new IllegalStateException("downstream unavailable")));

        assertDecision(request(ACTOR_ID.toString(), AccessAction.READ, AccessResourceType.ACCOUNT, ACCOUNT_ID),
                false, AccessDecision.SESSION_UNAVAILABLE);
    }

    @Test
    void nonUuidActorDoesNotAskForASession() {
        SessionGrantAccessAdapterImpl adapter = new SessionGrantAccessAdapterImpl(sessionManager);

        StepVerifier.create(adapter.decide(request("not-a-party", AccessAction.READ, AccessResourceType.PARTY, "party-1")))
                .assertNext(decision -> {
                    assertThat(decision.isAllowed()).isFalse();
                    assertThat(decision.getReasonCode()).isEqualTo(AccessDecision.ACTOR_UNKNOWN);
                })
                .verifyComplete();

        verify(sessionManager, never()).getSessionByPartyId(org.mockito.ArgumentMatchers.any());
    }

    private void assertDecision(AccessRequest request, boolean allowed, String reasonCode) {
        SessionGrantAccessAdapterImpl adapter = new SessionGrantAccessAdapterImpl(sessionManager);
        StepVerifier.create(adapter.decide(request))
                .assertNext(decision -> {
                    assertThat(decision.isAllowed()).isEqualTo(allowed);
                    assertThat(decision.getReasonCode()).isEqualTo(reasonCode);
                })
                .verifyComplete();
    }

    private static AccessRequest request(String actorId, AccessAction action, AccessResourceType type, String resourceId) {
        return AccessRequest.builder()
                .actorId(actorId)
                .action(action)
                .resourceType(type)
                .resourceId(resourceId)
                .build();
    }

    private static SessionContextDTO session(RoleScopeInfoDTO scope) {
        return SessionContextDTO.builder()
                .partyId(ACTOR_ID)
                .status(SessionContextDTO.SessionStatus.ACTIVE)
                .activeContracts(List.of(ContractInfoDTO.builder()
                        .isActive(true)
                        .roleInContract(RoleInfoDTO.builder()
                                .isActive(true)
                                .scopes(List.of(scope))
                                .build())
                        .build()))
                .build();
    }

    private static RoleScopeInfoDTO scope(String action, String resourceType, String resourceId) {
        return RoleScopeInfoDTO.builder()
                .actionType(action)
                .resourceType(resourceType)
                .resourceId(resourceId)
                .isActive(true)
                .build();
    }
}
