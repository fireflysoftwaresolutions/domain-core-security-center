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

package io.fireflysoftware.security.center.core.services;

import io.fireflysoftware.security.center.interfaces.dtos.ContractInfoDTO;
import io.fireflysoftware.security.center.interfaces.dtos.CustomerInfoDTO;
import io.fireflysoftware.security.center.interfaces.dtos.SessionContextDTO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.UUID;

/**
 * Service that aggregates session context from multiple microservices
 */
@Service("sessionAggregationService")
@RequiredArgsConstructor
@Slf4j
public class SessionAggregationServiceImpl {

    private final CustomerResolverServiceImpl customerResolverService;
    private final ContractResolverServiceImpl contractResolverService;

    /**
     * Aggregates complete session context for a partyId by fetching data from:
     * - customer-mgmt: Party/customer information
     * - contract-mgmt: Active contracts for the party
     * - reference-master-data: Role and scope information for each contract
     * - product-mgmt: Product information for each contract
     *
     * @param partyId The party identifier
     * @return Mono<SessionContextDTO> with aggregated session data
     */
    public Mono<SessionContextDTO> aggregateSessionContext(UUID partyId) {
        log.info("Aggregating session context for partyId: {}", partyId);

        return Mono.zip(
            customerResolverService.resolveCustomerInfo(partyId),
            contractResolverService.resolveActiveContracts(partyId)
        ).map(tuple -> {
            CustomerInfoDTO customerInfo = tuple.getT1();
            List<ContractInfoDTO> activeContracts = tuple.getT2();

            log.info("Successfully aggregated session for partyId: {} with {} active contracts",
                    partyId, activeContracts.size());

            return SessionContextDTO.builder()
                    .partyId(partyId)
                    .customerInfo(customerInfo)
                    .activeContracts(activeContracts)
                    .build();
        }).doOnError(error -> 
            log.error("Failed to aggregate session context for partyId: {}", partyId, error)
        );
    }
}
