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

import io.fireflysoftware.core.customer.sdk.api.*;
import io.fireflysoftware.core.customer.sdk.model.*;
import io.fireflysoftware.security.center.interfaces.dtos.PartyKind;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.LocalDate;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Unit tests for CustomerResolverServiceImpl.
 * Tests all enrichment scenarios with mocked SDK APIs.
 */
@ExtendWith(MockitoExtension.class)
class CustomerResolverServiceTest {

    @Mock
    private PartiesApi partiesApi;

    @Mock
    private NaturalPersonsApi naturalPersonsApi;

    @Mock
    private LegalEntitiesApi legalEntitiesApi;

    @Mock
    private EmailContactsApi emailContactsApi;

    @Mock
    private PhoneContactsApi phoneContactsApi;

    @InjectMocks
    private CustomerResolverServiceImpl customerResolverService;

    private UUID testPartyId;
    private UUID testTenantId;

    @BeforeEach
    void setUp() {
        testPartyId = UUID.randomUUID();
        testTenantId = UUID.randomUUID();
    }

    @Test
    void resolveCustomerInfo_naturalPerson_success() {
        // Given
        PartyDTO party = createPartyDTO(PartyDTO.PartyKindEnum.INDIVIDUAL);
        NaturalPersonDTO naturalPerson = createNaturalPersonDTO();
        PaginationResponseEmailContactDTO emailResponse = createEmailResponse("john.doe@example.com");
        PaginationResponsePhoneContactDTO phoneResponse = createPhoneResponse("+1234567890");

        when(partiesApi.getPartyById(eq(testPartyId), any())).thenReturn(Mono.just(party));
        when(naturalPersonsApi.getNaturalPersonByPartyId(eq(testPartyId), any())).thenReturn(Mono.just(naturalPerson));
        when(emailContactsApi.filterEmailContacts(eq(testPartyId), any(), any())).thenReturn(Mono.just(emailResponse));
        when(phoneContactsApi.filterPhoneContacts(eq(testPartyId), any(), any())).thenReturn(Mono.just(phoneResponse));

        // When & Then
        StepVerifier.create(customerResolverService.resolveCustomerInfo(testPartyId))
                .assertNext(customer -> {
                    assertThat(customer).isNotNull();
                    assertThat(customer.getPartyId()).isEqualTo(testPartyId);
                    assertThat(customer.getPartyKind()).isEqualTo(PartyKind.INDIVIDUAL);
                    assertThat(customer.getTenantId()).isEqualTo(testTenantId);
                    assertThat(customer.getFullName()).isEqualTo("John Michael Doe Smith");
                    assertThat(customer.getEmail()).isEqualTo("john.doe@example.com");
                    assertThat(customer.getPhoneNumber()).isEqualTo("+1234567890");
                    assertThat(customer.getIsActive()).isTrue();
                })
                .verifyComplete();

        verify(partiesApi).getPartyById(eq(testPartyId), any());
        verify(naturalPersonsApi).getNaturalPersonByPartyId(eq(testPartyId), any());
        verify(emailContactsApi).filterEmailContacts(eq(testPartyId), any(), any());
        verify(phoneContactsApi).filterPhoneContacts(eq(testPartyId), any(), any());
    }

    @Test
    void resolveCustomerInfo_legalEntity_success() {
        // Given
        PartyDTO party = createPartyDTO(PartyDTO.PartyKindEnum.ORGANIZATION);
        LegalEntityDTO legalEntity = createLegalEntityDTO();
        PaginationResponseEmailContactDTO emailResponse = createEmailResponse("contact@company.com");
        PaginationResponsePhoneContactDTO phoneResponse = createPhoneResponse("+9876543210");

        when(partiesApi.getPartyById(eq(testPartyId), any())).thenReturn(Mono.just(party));
        when(legalEntitiesApi.getLegalEntityByPartyId(eq(testPartyId), any())).thenReturn(Mono.just(legalEntity));
        when(emailContactsApi.filterEmailContacts(eq(testPartyId), any(), any())).thenReturn(Mono.just(emailResponse));
        when(phoneContactsApi.filterPhoneContacts(eq(testPartyId), any(), any())).thenReturn(Mono.just(phoneResponse));

        // When & Then
        StepVerifier.create(customerResolverService.resolveCustomerInfo(testPartyId))
                .assertNext(customer -> {
                    assertThat(customer).isNotNull();
                    assertThat(customer.getPartyId()).isEqualTo(testPartyId);
                    assertThat(customer.getPartyKind()).isEqualTo(PartyKind.ORGANIZATION);
                    assertThat(customer.getFullName()).isEqualTo("Acme Corporation");
                    assertThat(customer.getEmail()).isEqualTo("contact@company.com");
                    assertThat(customer.getPhoneNumber()).isEqualTo("+9876543210");
                })
                .verifyComplete();

        verify(partiesApi).getPartyById(eq(testPartyId), any());
        verify(legalEntitiesApi).getLegalEntityByPartyId(eq(testPartyId), any());
        verify(naturalPersonsApi, never()).getNaturalPersonByPartyId(eq(testPartyId), any());
    }

    @Test
    void resolveCustomerInfo_naturalPersonWithoutMiddleName_success() {
        // Given
        PartyDTO party = createPartyDTO(PartyDTO.PartyKindEnum.INDIVIDUAL);
        NaturalPersonDTO naturalPerson = new NaturalPersonDTO();
        naturalPerson.setPartyId(testPartyId);
        naturalPerson.setGivenName("Jane");
        naturalPerson.setFamilyName("Doe");
        // No middle name or familyName2

        when(partiesApi.getPartyById(eq(testPartyId), any())).thenReturn(Mono.just(party));
        when(naturalPersonsApi.getNaturalPersonByPartyId(eq(testPartyId), any())).thenReturn(Mono.just(naturalPerson));
        when(emailContactsApi.filterEmailContacts(eq(testPartyId), any(), any()))
                .thenReturn(Mono.just(createEmailResponse(null)));
        when(phoneContactsApi.filterPhoneContacts(eq(testPartyId), any(), any()))
                .thenReturn(Mono.just(createPhoneResponse(null)));

        // When & Then
        StepVerifier.create(customerResolverService.resolveCustomerInfo(testPartyId))
                .assertNext(customer -> {
                    assertThat(customer.getFullName()).isEqualTo("Jane Doe");
                    assertThat(customer.getEmail()).isNull();
                    assertThat(customer.getPhoneNumber()).isNull();
                })
                .verifyComplete();
    }

    @Test
    void resolveCustomerInfo_legalEntityWithLegalName_success() {
        // Given
        PartyDTO party = createPartyDTO(PartyDTO.PartyKindEnum.ORGANIZATION);
        LegalEntityDTO legalEntity = new LegalEntityDTO();
        legalEntity.setPartyId(testPartyId);
        legalEntity.setLegalName("Acme Legal Name LLC");
        // No trade name

        when(partiesApi.getPartyById(eq(testPartyId), any())).thenReturn(Mono.just(party));
        when(legalEntitiesApi.getLegalEntityByPartyId(eq(testPartyId), any())).thenReturn(Mono.just(legalEntity));
        when(emailContactsApi.filterEmailContacts(eq(testPartyId), any(), any()))
                .thenReturn(Mono.just(createEmailResponse(null)));
        when(phoneContactsApi.filterPhoneContacts(eq(testPartyId), any(), any()))
                .thenReturn(Mono.just(createPhoneResponse(null)));

        // When & Then
        StepVerifier.create(customerResolverService.resolveCustomerInfo(testPartyId))
                .assertNext(customer -> {
                    assertThat(customer.getFullName()).isEqualTo("Acme Legal Name LLC");
                })
                .verifyComplete();
    }

    @Test
    void resolveCustomerInfo_naturalPersonFetchFails_propagatesError() {
        // Given
        PartyDTO party = createPartyDTO(PartyDTO.PartyKindEnum.INDIVIDUAL);

        when(partiesApi.getPartyById(eq(testPartyId), any())).thenReturn(Mono.just(party));
        when(naturalPersonsApi.getNaturalPersonByPartyId(eq(testPartyId), any()))
                .thenReturn(Mono.error(new RuntimeException("Natural person not found")));
        // No need to mock email/phone contacts - error happens before they're called

        // When & Then - Error should propagate, no fallback
        StepVerifier.create(customerResolverService.resolveCustomerInfo(testPartyId))
                .expectErrorMatches(throwable ->
                    throwable instanceof RuntimeException &&
                    throwable.getMessage().equals("Natural person not found"))
                .verify();
    }

    @Test
    void resolveCustomerInfo_emailFetchFails_continuesWithoutEmail() {
        // Given
        PartyDTO party = createPartyDTO(PartyDTO.PartyKindEnum.INDIVIDUAL);
        NaturalPersonDTO naturalPerson = createNaturalPersonDTO();

        when(partiesApi.getPartyById(eq(testPartyId), any())).thenReturn(Mono.just(party));
        when(naturalPersonsApi.getNaturalPersonByPartyId(eq(testPartyId), any())).thenReturn(Mono.just(naturalPerson));
        when(emailContactsApi.filterEmailContacts(eq(testPartyId), any(), any()))
                .thenReturn(Mono.error(new RuntimeException("Email service down")));
        when(phoneContactsApi.filterPhoneContacts(eq(testPartyId), any(), any()))
                .thenReturn(Mono.just(createPhoneResponse("+1234567890")));

        // When & Then
        StepVerifier.create(customerResolverService.resolveCustomerInfo(testPartyId))
                .assertNext(customer -> {
                    assertThat(customer.getEmail()).isNull();
                    assertThat(customer.getPhoneNumber()).isEqualTo("+1234567890");
                    assertThat(customer.getFullName()).isEqualTo("John Michael Doe Smith");
                })
                .verifyComplete();
    }

    @Test
    void resolveCustomerInfo_partyNotFound_propagatesError() {
        // Given
        when(partiesApi.getPartyById(eq(testPartyId), any()))
                .thenReturn(Mono.error(new RuntimeException("Party not found")));

        // When & Then - Error should propagate, no fallback
        StepVerifier.create(customerResolverService.resolveCustomerInfo(testPartyId))
                .expectErrorMatches(throwable ->
                    throwable instanceof RuntimeException &&
                    throwable.getMessage().equals("Party not found"))
                .verify();

        verify(partiesApi).getPartyById(eq(testPartyId), any());
        verifyNoInteractions(naturalPersonsApi, legalEntitiesApi, emailContactsApi, phoneContactsApi);
    }

    @Test
    void resolveCustomerInfo_unknownPartyKind_propagatesError() {
        // Given
        PartyDTO party = createPartyDTO(null);
        party.setPartyKind(null);

        when(partiesApi.getPartyById(eq(testPartyId), any())).thenReturn(Mono.just(party));
        // No need to mock email/phone contacts - error happens before they're called

        // When & Then - Error should propagate for unknown party kind
        StepVerifier.create(customerResolverService.resolveCustomerInfo(testPartyId))
                .expectErrorMatches(throwable ->
                    throwable instanceof IllegalArgumentException &&
                    throwable.getMessage().contains("Unknown party kind"))
                .verify();
    }

    @Test
    void resolveCustomerInfo_multipleEmailsReturnsPrimary() {
        // Given
        PartyDTO party = createPartyDTO(PartyDTO.PartyKindEnum.INDIVIDUAL);
        NaturalPersonDTO naturalPerson = createNaturalPersonDTO();
        
        EmailContactDTO primaryEmail = createEmailContactDTO("primary@example.com", true);
        EmailContactDTO secondaryEmail = createEmailContactDTO("secondary@example.com", false);
        PaginationResponseEmailContactDTO emailResponse = new PaginationResponseEmailContactDTO();
        emailResponse.setContent(List.of(secondaryEmail, primaryEmail)); // Primary is second

        when(partiesApi.getPartyById(eq(testPartyId), any())).thenReturn(Mono.just(party));
        when(naturalPersonsApi.getNaturalPersonByPartyId(eq(testPartyId), any())).thenReturn(Mono.just(naturalPerson));
        when(emailContactsApi.filterEmailContacts(eq(testPartyId), any(), any()))
                .thenReturn(Mono.just(emailResponse));
        when(phoneContactsApi.filterPhoneContacts(eq(testPartyId), any(), any()))
                .thenReturn(Mono.just(createPhoneResponse(null)));

        // When & Then
        StepVerifier.create(customerResolverService.resolveCustomerInfo(testPartyId))
                .assertNext(customer -> {
                    assertThat(customer.getEmail()).isEqualTo("primary@example.com");
                })
                .verifyComplete();
    }

    // ========== Helper Methods ==========

    private PartyDTO createPartyDTO(PartyDTO.PartyKindEnum partyKind) {
        PartyDTO dto = new PartyDTO();
        dto.setPartyKind(partyKind);
        dto.setTenantId(testTenantId);
        dto.setPreferredLanguage("en");
        // Use reflection to set partyId (read-only field)
        try {
            java.lang.reflect.Field field = PartyDTO.class.getDeclaredField("partyId");
            field.setAccessible(true);
            field.set(dto, testPartyId);
        } catch (Exception e) {
            throw new RuntimeException("Failed to set partyId", e);
        }
        return dto;
    }

    private NaturalPersonDTO createNaturalPersonDTO() {
        NaturalPersonDTO dto = new NaturalPersonDTO();
        dto.setPartyId(testPartyId);
        dto.setGivenName("John");
        dto.setMiddleName("Michael");
        dto.setFamilyName("Doe");
        dto.setSecondFamilyName("Smith");
        dto.setDateOfBirth(LocalDate.of(1990, 1, 1));
        return dto;
    }

    private LegalEntityDTO createLegalEntityDTO() {
        LegalEntityDTO dto = new LegalEntityDTO();
        dto.setPartyId(testPartyId);
        dto.setTradeName("Acme Corporation");
        dto.setLegalName("Acme Corporation LLC");
        dto.setRegistrationNumber("REG123456");
        return dto;
    }

    private PaginationResponseEmailContactDTO createEmailResponse(String email) {
        PaginationResponseEmailContactDTO response = new PaginationResponseEmailContactDTO();
        if (email != null) {
            EmailContactDTO emailContact = createEmailContactDTO(email, true);
            response.setContent(List.of(emailContact));
        } else {
            response.setContent(List.of());
        }
        return response;
    }

    private EmailContactDTO createEmailContactDTO(String email, boolean isPrimary) {
        EmailContactDTO dto = new EmailContactDTO();
        dto.setPartyId(testPartyId);
        dto.setEmail(email);
        dto.setEmailKind(EmailContactDTO.EmailKindEnum.PERSONAL);
        dto.setIsPrimary(isPrimary);
        return dto;
    }

    private PaginationResponsePhoneContactDTO createPhoneResponse(String phoneNumber) {
        PaginationResponsePhoneContactDTO response = new PaginationResponsePhoneContactDTO();
        if (phoneNumber != null) {
            PhoneContactDTO phoneContact = new PhoneContactDTO();
            phoneContact.setPartyId(testPartyId);
            phoneContact.setPhoneNumber(phoneNumber);
            phoneContact.setPhoneKind(PhoneContactDTO.PhoneKindEnum.MOBILE);
            phoneContact.setIsPrimary(true);
            response.setContent(List.of(phoneContact));
        } else {
            response.setContent(List.of());
        }
        return response;
    }
}
