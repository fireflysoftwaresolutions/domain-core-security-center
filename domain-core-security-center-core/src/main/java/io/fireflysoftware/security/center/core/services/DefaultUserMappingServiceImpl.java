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

import io.fireflysoftware.core.customer.sdk.api.EmailContactsApi;
import io.fireflysoftware.core.customer.sdk.api.PartiesApi;
import io.fireflysoftware.core.customer.sdk.model.*;
import org.fireflyframework.security.idp.dtos.UserInfoResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Default implementation of UserMappingService using customer-mgmt SDK.
 *
 * <p>This implementation queries the customer-mgmt service to map IDP users
 * to Firefly partyIds by searching through all parties and their email contacts.
 *
 * <p><strong>Lookup Strategy:</strong></p>
 * <ol>
 *   <li>Try to find party by email from IDP user info (searches all parties' email contacts)</li>
 *   <li>If email lookup fails, try sourceSystem field lookup (for IDP username mapping)</li>
 *   <li>If both fail, throw IllegalStateException - party MUST exist before authentication</li>
 * </ol>
 *
 * <p><strong>Important:</strong> This implementation requires that parties exist in customer-mgmt
 * before users can authenticate. If a party is not found, authentication will fail with an error.
 *
 * <p><strong>Performance Note:</strong> Email lookup searches through all parties which may be slow
 * for large datasets. For production use, consider:
 * <ul>
 *   <li>Adding a dedicated email search endpoint in customer-mgmt</li>
 *   <li>Storing IDP subject ID in party's sourceSystem field (format: "idp:username")</li>
 *   <li>Implementing caching for email-to-partyId mappings</li>
 *   <li>Providing your own optimized {@code @Service} implementation of {@link UserMappingService}</li>
 * </ul>
 *
 * <p><strong>To auto-provision parties:</strong> Override this service with a custom implementation
 * that creates parties in customer-mgmt when they don't exist.
 */
@Service("defaultUserMappingService")
@RequiredArgsConstructor
@Slf4j
public class DefaultUserMappingServiceImpl implements UserMappingService {

    private final PartiesApi partiesApi;
    private final EmailContactsApi emailContactsApi;

    @Override
    public Mono<UUID> mapToPartyId(UserInfoResponse userInfo, String username) {
        log.debug("Mapping IDP user to partyId - email: {}, username: {}",
                userInfo.getEmail(), username);

        // First, try to find party by email
        if (userInfo.getEmail() != null && !userInfo.getEmail().isBlank()) {
            return findPartyByEmail(userInfo.getEmail())
                    .onErrorResume(error -> {
                        log.debug("Email lookup failed, trying username lookup: {}", error.getMessage());
                        String usernameToUse = username != null ? username : userInfo.getPreferredUsername();
                        if (usernameToUse != null) {
                            return findPartyByUsername(usernameToUse);
                        }
                        return Mono.error(new IllegalStateException(
                                "No party found for IDP user. Email: " + userInfo.getEmail() +
                                ", Username: null. Party must exist in customer-mgmt before authentication."));
                    });
        }

        // If no email, try username
        if (username != null || userInfo.getPreferredUsername() != null) {
            return findPartyByUsername(username != null ? username : userInfo.getPreferredUsername());
        }

        // No email and no username - cannot map
        return Mono.error(new IllegalStateException(
                "Cannot map IDP user to partyId. No email or username provided. " +
                "IDP user sub: " + userInfo.getSub()));
    }

    /**
     * Find party by email address using SDK.
     *
     * <p>Strategy: Get all parties and check their email contacts.
     * This is not optimal for large datasets but works for the general case.
     *
     * <p>For production optimization, consider:
     * <ul>
     *   <li>Adding a dedicated email search endpoint in customer-mgmt</li>
     *   <li>Using a search service (Elasticsearch, etc.)</li>
     *   <li>Caching email-to-partyId mappings</li>
     * </ul>
     */
    private Mono<UUID> findPartyByEmail(String email) {
        log.debug("Looking up party by email using SDK: {}", email);

        // Create filter to get all parties (paginated)
        FilterRequestPartyDTO filter = new FilterRequestPartyDTO();
        PaginationRequest pagination = new PaginationRequest();
        pagination.setPageNumber(0);
        pagination.setPageSize(100); // Process in batches of 100
        filter.setPagination(pagination);

        return partiesApi.filterParties(filter, UUID.randomUUID().toString())
                .expand(response -> {
                    // If there are more pages, fetch them
                    if (response.getCurrentPage() != null &&
                        response.getCurrentPage() < response.getTotalPages() - 1) {
                        PaginationRequest nextPage = new PaginationRequest();
                        nextPage.setPageNumber(response.getCurrentPage() + 1);
                        nextPage.setPageSize(100);
                        FilterRequestPartyDTO nextFilter = new FilterRequestPartyDTO();
                        nextFilter.setPagination(nextPage);
                        return partiesApi.filterParties(nextFilter, UUID.randomUUID().toString());
                    }
                    return Mono.empty();
                })
                .flatMap(response -> {
                    // Check each party's email contacts
                    if (response.getContent() == null || response.getContent().isEmpty()) {
                        return Flux.empty();
                    }

                    return Flux.fromIterable(response.getContent())
                            .flatMap(item -> {
                                Map<String, Object> map = (Map<String, Object>) item;
                                UUID partyId = UUID.fromString((String) map.get("partyId"));
                                return checkPartyEmail(partyId, email)
                                        .mapNotNull(hasEmail -> hasEmail ? partyId : null);
                            })
                            .filter(Objects::nonNull);
                })
                .next() // Get the first match
                .doOnSuccess(partyId -> {
                    if (partyId != null) {
                        log.info("Found party by email: {} -> {}", email, partyId);
                    }
                })
                .switchIfEmpty(Mono.error(new IllegalStateException(
                        "No party found with email: " + email +
                        ". Party must exist in customer-mgmt before authentication.")));
    }

    /**
     * Check if a party has a specific email address
     */
    private Mono<Boolean> checkPartyEmail(UUID partyId, String email) {
        FilterRequestEmailContactDTO filter = new FilterRequestEmailContactDTO();
        EmailContactDTO emailFilter = new EmailContactDTO();
        emailFilter.setEmail(email);
        PaginationRequest pagination = new PaginationRequest();
        pagination.setPageNumber(0);
        pagination.setPageSize(100); // Process in batches of 100
        filter.setPagination(pagination);
        filter.setFilters(emailFilter);
        filter.setPagination(pagination);

        return emailContactsApi.filterEmailContacts(partyId, filter, UUID.randomUUID().toString())
                .map(response -> response != null && response.getContent() != null && !response.getContent().isEmpty())
                .onErrorResume(e -> {
                    log.error("Error checking email for partyId {}: {}", partyId, e.getMessage(), e);
                    return Mono.just(false);
                });
    }

    /**
     * Find party by username using SDK filtering on sourceSystem field.
     *
     * <p>This assumes that parties have their IDP username stored in the sourceSystem field
     * with a format like "idp:username".
     *
     * <p><strong>Important:</strong> Parties must be created with sourceSystem field set to
     * "idp:username" for this lookup to work.
     */
    private Mono<UUID> findPartyByUsername(String username) {
        if (username == null) {
            return Mono.error(new IllegalArgumentException("Username is null"));
        }

        log.debug("Looking up party by username using SDK: {}", username);

        // Create filter to search by sourceSystem field
        FilterRequestPartyDTO filter = new FilterRequestPartyDTO();
        PartyDTO partyFilter = new PartyDTO();
        partyFilter.setSourceSystem("idp:" + username);
        filter.setFilters(partyFilter);

        PaginationRequest pagination = new PaginationRequest();
        pagination.setPageNumber(0);
        pagination.setPageSize(10); // Should only find one
        filter.setPagination(pagination);

        return partiesApi.filterParties(filter, UUID.randomUUID().toString())
                .flatMap(response -> {
                    if (response.getContent() != null && !response.getContent().isEmpty()) {
                        PartyDTO firstItem = response.getContent().getFirst();
                        if (firstItem != null) {
                            UUID partyId = firstItem.getPartyId();
                            log.info("Found party by username: {} -> {}", username, partyId);
                            return Mono.just(Objects.requireNonNull(partyId));
                        }
                    }
                    return Mono.error(new IllegalStateException(
                            "No party found with username: " + username +
                            ". Party must exist in customer-mgmt with sourceSystem='idp:" + username + "' before authentication."));
                });
    }
}
