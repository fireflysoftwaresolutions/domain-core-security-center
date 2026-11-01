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

import io.fireflysoftware.core.product.sdk.api.ProductApi;
import io.fireflysoftware.core.product.sdk.model.ProductDTO;
import io.fireflysoftware.common.reference.master.data.sdk.api.ContractRoleApi;
import io.fireflysoftware.common.reference.master.data.sdk.api.ContractRoleScopeApi;
import io.fireflysoftware.common.reference.master.data.sdk.model.ContractRoleDTO;
import io.fireflysoftware.common.reference.master.data.sdk.model.ContractRoleScopeDTO;
import io.fireflysoftware.core.contract.sdk.api.ContractPartiesApi;
import io.fireflysoftware.core.contract.sdk.api.ContractsApi;
import io.fireflysoftware.core.contract.sdk.api.GlobalContractPartiesApi;
import io.fireflysoftware.core.contract.sdk.model.ContractDTO;
import io.fireflysoftware.core.contract.sdk.model.ContractPartyDTO;
import io.fireflysoftware.security.center.interfaces.dtos.ContractInfoDTO;
import io.fireflysoftware.security.center.interfaces.dtos.ProductInfoDTO;
import io.fireflysoftware.security.center.interfaces.dtos.RoleInfoDTO;
import io.fireflysoftware.security.center.interfaces.dtos.RoleScopeInfoDTO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Service for resolving contracts with their associated roles and products using SDK.
 * 
 * <p>Uses OpenAPI-generated SDK clients to fetch contract, role, and product information
 * from downstream microservices and maps them to Security Center DTOs.
 */
@Service("contractResolverService")
@RequiredArgsConstructor
@Slf4j
public class ContractResolverServiceImpl {

    private final ContractsApi contractsApi;
    private final ContractPartiesApi contractPartiesApi;
    private final GlobalContractPartiesApi globalContractPartiesApi;
    private final ProductApi productApi;
    private final ContractRoleApi contractRoleApi;
    private final ContractRoleScopeApi contractRoleScopeApi;

    /**
     * Resolves all active contracts for a party, including:
     * - Contract details
     * - Role information from reference-master-data
     * - Role scopes (permissions) from reference-master-data
     * - Product information from product-mgmt
     *
     * @param partyId The party identifier
     * @return Mono<List<ContractInfoDTO>> with complete contract information
     */
    public Mono<List<ContractInfoDTO>> resolveActiveContracts(UUID partyId) {
        log.debug("Resolving active contracts for partyId: {}", partyId);

        return fetchContractPartiesForParty(partyId)
                .flatMap(this::enrichContractWithDetails)
                .collectList()
                .doOnSuccess(contracts -> 
                    log.info("Resolved {} active contracts for partyId: {}", contracts.size(), partyId))
                .doOnError(error -> 
                    log.error("Failed to resolve contracts for partyId: {}", partyId, error));
    }

    /**
     * Fetches all ContractParty records for a given partyId from contract-mgmt using SDK.
     * 
     * <p>Uses GlobalContractPartiesApi.getContractPartiesByPartyId() which queries
     * the global endpoint GET /api/v1/contract-parties?partyId={partyId}&isActive=true
     */
    private Flux<ContractInfoDTO> fetchContractPartiesForParty(UUID partyId) {
        log.debug("Fetching contract parties for partyId: {}", partyId);
        
        return globalContractPartiesApi.getContractPartiesByPartyId(partyId, true, UUID.randomUUID().toString())
                .flatMapMany(response -> Flux.fromIterable(Objects.requireNonNull(response.getContent())))
                .map(this::mapContractPartyDTOToContractInfo)
                .doOnNext(contractInfo -> 
                    log.debug("Found contract party: contractId={}, roleId={}", 
                            contractInfo.getContractId(), contractInfo.getRoleInContract().getRoleId()))
                .doOnError(error -> 
                    log.error("Failed to fetch contract parties for partyId: {}", partyId, error))
                .onErrorResume(error -> {
                    log.warn("No contracts found for partyId: {}, returning empty list. Error: {}", 
                            partyId, error.getMessage());
                    return Flux.empty();
                });
    }

    /**
     * Enriches a contract with role, scopes, and product information
     */
    private Mono<ContractInfoDTO> enrichContractWithDetails(ContractInfoDTO contractInfo) {
        UUID contractId = contractInfo.getContractId();
        log.debug("Enriching contract: {}", contractId);

        // First fetch the contract to get productId
        return fetchContract(contractId)
            .flatMap(fullContract -> {
                // Now we have productId from the contract
                UUID productId = fullContract.getProduct() != null && fullContract.getProduct().getProductId() != null 
                    ? fullContract.getProduct().getProductId() 
                    : null;

                // Fetch role (required) and product (optional)
                Mono<RoleInfoDTO> roleMono = fetchRoleWithScopes(contractInfo.getRoleInContract().getRoleId());

                if (productId != null) {
                    // Both role and product
                    Mono<ProductInfoDTO> productMono = fetchProduct(productId);
                    return Mono.zip(roleMono, productMono)
                            .map(tuple -> {
                                RoleInfoDTO roleWithScopes = tuple.getT1();
                                ProductInfoDTO productInfo = tuple.getT2();
                                return contractInfo.toBuilder()
                                        .contractNumber(fullContract.getContractNumber())
                                        .contractStatus(fullContract.getContractStatus())
                                        .startDate(fullContract.getStartDate())
                                        .endDate(fullContract.getEndDate())
                                        .roleInContract(roleWithScopes)
                                        .product(productInfo)
                                        .build();
                            });
                } else {
                    // Only role, no product
                    return roleMono.map(roleWithScopes ->
                            contractInfo.toBuilder()
                                    .contractNumber(fullContract.getContractNumber())
                                    .contractStatus(fullContract.getContractStatus())
                                    .startDate(fullContract.getStartDate())
                                    .endDate(fullContract.getEndDate())
                                    .roleInContract(roleWithScopes)
                                    .product(null)
                                    .build());
                }
            });
    }


    /**
     * Fetches role information with all its scopes from reference-master-data
     */
    private Mono<RoleInfoDTO> fetchRoleWithScopes(UUID roleId) {
        log.debug("Fetching role with scopes for roleId: {}", roleId);

        return Mono.zip(
            fetchRole(roleId),
            fetchRoleScopes(roleId)
        ).map(tuple -> {
            RoleInfoDTO role = tuple.getT1();
            List<RoleScopeInfoDTO> scopes = tuple.getT2();

            return role.toBuilder()
                    .scopes(scopes)
                    .build();
        });
    }




    /**
     * Fetches full contract details from contract-mgmt using SDK.
     */
    private Mono<ContractInfoDTO> fetchContract(UUID contractId) {
        return contractsApi.getContractById(contractId, UUID.randomUUID().toString())
                .map(this::mapContractDTOToContractInfo)
                .doOnSuccess(contract -> 
                    log.debug("Fetched contract: {}", contractId))
                .doOnError(error -> 
                    log.error("Failed to fetch contract: {}", contractId, error));
    }

    /**
     * Fetches role details from reference-master-data using SDK.
     */
    private Mono<RoleInfoDTO> fetchRole(UUID roleId) {
        return contractRoleApi.getContractRole(roleId, UUID.randomUUID().toString())
                .map(this::mapContractRoleDTOToRoleInfo)
                .doOnSuccess(role ->
                    log.debug("Fetched role: {}", roleId))
                .doOnError(error ->
                    log.error("Failed to fetch role: {}", roleId, error));
    }

    /**
     * Fetches all active scopes (permissions) for a role from reference-master-data using SDK.
     */
    private Mono<List<RoleScopeInfoDTO>> fetchRoleScopes(UUID roleId) {
        return contractRoleScopeApi.getActiveScopesByRoleId(roleId, UUID.randomUUID().toString())
                .map(this::mapContractRoleScopeDTOToRoleScopeInfo)
                .collectList()
                .doOnSuccess(scopes ->
                        log.debug("Fetched {} scopes for roleId: {}", scopes.size(), roleId))
                .doOnError(error ->
                        log.error("Failed to fetch role scopes for roleId: {}", roleId, error))
                .onErrorResume(error -> {
                    log.warn("No scopes found for roleId: {}", roleId);
                    return Mono.just(Collections.emptyList());
                });
    }

    /**
     * Fetches product information from product-mgmt using SDK.
     */
    private Mono<ProductInfoDTO> fetchProduct(UUID productId) {
        return productApi.getProductById(productId, UUID.randomUUID().toString())
                .map(this::mapProductDTOToProductInfo)
                .doOnSuccess(product ->
                    log.debug("Fetched product: {}", productId))
                .doOnError(error ->
                    log.error("Failed to fetch product: {}", productId, error));
    }

    // ========== DTO Mapping Methods ==========

    /**
     * Maps SDK ContractPartyDTO to partial ContractInfoDTO.
     * Additional enrichment is done by fetchContract(), fetchRole(), etc.
     */
    private ContractInfoDTO mapContractPartyDTOToContractInfo(ContractPartyDTO contractPartyDTO) {
        // Create basic role info with just the ID - will be enriched later
        RoleInfoDTO basicRole = RoleInfoDTO.builder()
                .roleId(contractPartyDTO.getRoleInContractId())
                .build();
        
        // Create basic product info - will be enriched later
        ProductInfoDTO basicProduct = ProductInfoDTO.builder()
                .build();
        
        return ContractInfoDTO.builder()
                .contractId(contractPartyDTO.getContractId())
                .roleInContract(basicRole)
                .product(basicProduct)
                .build();
    }

    /**
     * Maps SDK ContractDTO to Security Center ContractInfoDTO.
     */
    private ContractInfoDTO mapContractDTOToContractInfo(ContractDTO contractDTO) {
        // Create basic product info with productId from ContractDTO
        ProductInfoDTO productInfo = null;
        if (contractDTO.getProductId() != null) {
            productInfo = ProductInfoDTO.builder()
                    .productId(contractDTO.getProductId())
                    .build();
        }
        
        return ContractInfoDTO.builder()
                .contractId(contractDTO.getContractId())
                .contractNumber(contractDTO.getContractNumber())
                .contractStatus(contractDTO.getContractStatus().getValue())
                .startDate(contractDTO.getStartDate())
                .endDate(contractDTO.getEndDate())
                .product(productInfo)
                .build();
    }

    /**
     * Maps SDK ContractRoleDTO to Security Center RoleInfoDTO.
     */
    private RoleInfoDTO mapContractRoleDTOToRoleInfo(ContractRoleDTO roleDTO) {
        return RoleInfoDTO.builder()
                .roleId(roleDTO.getRoleId())
                .roleCode(roleDTO.getRoleCode())
                .name(roleDTO.getName())
                .description(roleDTO.getDescription())
                .isActive(roleDTO.getIsActive())
                .scopes(Collections.emptyList()) // Will be populated separately
                .build();
    }

    /**
     * Maps SDK ContractRoleScopeDTO to Security Center RoleScopeInfoDTO.
     */
    private RoleScopeInfoDTO mapContractRoleScopeDTOToRoleScopeInfo(ContractRoleScopeDTO scopeDTO) {
        return RoleScopeInfoDTO.builder()
                .scopeId(scopeDTO.getScopeId())
                .scopeCode(scopeDTO.getScopeCode())
                .scopeName(scopeDTO.getScopeName())
                .description(scopeDTO.getDescription())
                .build();
    }

    /**
     * Maps SDK ProductDTO to Security Center ProductInfoDTO.
     */
    private ProductInfoDTO mapProductDTOToProductInfo(ProductDTO productDTO) {
        return ProductInfoDTO.builder()
                .productId(productDTO.getProductId())
                .productCode(productDTO.getProductCode())
                .productName(productDTO.getProductName())
                .productStatus(productDTO.getProductStatus() != null ?
                        productDTO.getProductStatus().getValue() : "UNKNOWN")
                .build();
    }
}
