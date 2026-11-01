/* Copyright 2026 Firefly Software Foundation. Licensed under the Apache License, Version 2.0. */
package io.fireflysoftware.security.center.core.impl;

import io.fireflysoftware.security.center.core.services.SessionAggregationServiceImpl;
import io.fireflysoftware.security.center.core.services.AuthenticationServiceImpl;
import io.fireflysoftware.security.center.core.services.UserMappingService;
import io.fireflysoftware.security.center.interfaces.dtos.SessionContextDTO;
import io.fireflysoftware.security.center.session.IdentityPort;
import org.fireflyframework.cache.core.CacheAdapter;
import org.fireflyframework.cache.core.CacheHealth;
import org.fireflyframework.cache.core.CacheStats;
import org.fireflyframework.cache.core.CacheType;
import org.fireflyframework.cache.manager.FireflyCacheManager;
import org.fireflyframework.security.api.domain.SecurityPrincipal;
import org.fireflyframework.security.spi.SecurityContextPort;
import org.fireflyframework.security.idp.adapter.IdpAdapter;
import org.fireflyframework.security.idp.dtos.LoginRequest;
import org.fireflyframework.security.idp.dtos.RefreshRequest;
import org.fireflyframework.security.idp.dtos.TokenResponse;
import org.fireflyframework.security.idp.dtos.UserInfoResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.test.util.ReflectionTestUtils;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Sinks;
import reactor.test.StepVerifier;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class FireflySessionManagerImplTest {

    private static final Object PRINCIPAL = new Object();
    private static final UUID PARTY_A = UUID.fromString("11111111-1111-4111-8111-111111111111");
    private static final UUID PARTY_B = UUID.fromString("22222222-2222-4222-8222-222222222222");
    private static final Instant NOW = Instant.parse("2026-10-31T12:00:00Z");

    @Test
    void missingNamespaceCannotCreateOrReadAnUnscopedContext() {
        var f = new Fixture();
        StepVerifier.create(f.manager.createSession(PARTY_A)).expectError(IllegalStateException.class).verify();
        assertThat(f.aggregations.get()).isZero();
        assertThat(f.cache.values).isEmpty();
    }

    @Test
    void legacyConstructorFailsClosed() {
        var f = new Fixture();
        var legacy = new FireflySessionManagerImpl(f.aggregation, new FireflyCacheManager(f.cache));
        StepVerifier.create(legacy.getSessionByPartyId(PARTY_A)).expectError(IllegalStateException.class).verify();
    }

    @Test
    void blankTenantOrExpiredCredentialCannotCreateANamespace() {
        var f = new Fixture();
        StepVerifier.create(f.in(f.manager.createSession(PARTY_A), f.principal("https://issuer.example", " ")))
                .expectError(IllegalStateException.class).verify();
        var expired = f.actorA.toBuilder().claims(Map.of("exp", NOW)).build();
        StepVerifier.create(f.in(f.manager.createSession(PARTY_A), expired))
                .expectError(IllegalStateException.class).verify();
        assertThat(f.cache.values).isEmpty();
    }

    @Test
    void explicitCreationIsCachedButLookupNeverAggregates() {
        var f = new Fixture();
        var created = f.create(PARTY_A, f.actorA);

        assertThat(f.in(f.manager.getSessionBySessionId(created.getSessionId()), f.actorA).block().getPartyId())
                .isEqualTo(PARTY_A);
        assertThat(f.in(f.manager.getSessionByPartyId(PARTY_A), f.actorA).block().getSessionId())
                .isEqualTo(created.getSessionId());
        assertThat(f.aggregations.get()).isEqualTo(1);
    }

    @Test
    void absentPartyLookupCannotCreateAnAuthenticatedSession() {
        var f = new Fixture();
        StepVerifier.create(f.in(f.manager.getSessionByPartyId(PARTY_A), f.actorA)).verifyComplete();
        assertThat(f.aggregations.get()).isZero();
    }

    @Test
    void absentSessionLookupAndRefreshCannotRecreateItsPartyFromTheIdentifier() {
        var f = new Fixture();
        var id = "session_11111111-1111-4111-8111-111111111111_33333333-3333-4333-8333-333333333333";
        StepVerifier.create(f.in(f.manager.getSessionBySessionId(id), f.actorA)).verifyComplete();
        StepVerifier.create(f.in(f.manager.refreshSession(id), f.actorA)).verifyComplete();
        assertThat(f.aggregations.get()).isZero();
    }

    @Test
    void suppliedMissingSessionIdentifierIsLookupOnly() {
        var f = new Fixture();
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/api/v1/sessions")
                .header("X-Party-Id", PARTY_A.toString())
                .header("X-Session-Id", "session_11111111-1111-4111-8111-111111111111_33333333-3333-4333-8333-333333333333"));
        StepVerifier.create(f.in(f.manager.createOrGetSession(exchange), f.actorA)).verifyComplete();
        assertThat(f.aggregations.get()).isZero();
    }

    @Test
    void explicitExchangeCreationWithoutSessionIdentifierRemainsAvailable() {
        var f = new Fixture();
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/api/v1/sessions")
                .header("X-Party-Id", PARTY_A.toString()));
        var created = f.in(f.manager.createOrGetSession(exchange), f.actorA).block();
        assertThat(created.getPartyId()).isEqualTo(PARTY_A);
        assertThat(created.getSessionId()).startsWith("session_");
    }

    @Test
    void foreignPartySessionCannotBeReturnedOrOverwrittenByCreateOrGet() {
        var f = new Fixture();
        var foreign = f.create(PARTY_B, f.actorA);
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/api/v1/sessions")
                .header("X-Party-Id", PARTY_A.toString()).header("X-Session-Id", foreign.getSessionId()));

        StepVerifier.create(f.in(f.manager.createOrGetSession(exchange), f.actorA))
                .expectError(IllegalArgumentException.class).verify();
        assertThat(f.in(f.manager.getSessionBySessionId(foreign.getSessionId()), f.actorA).block().getPartyId())
                .isEqualTo(PARTY_B);
        assertThat(f.aggregations.get()).isEqualTo(1);
    }

    @Test
    void samePartyInAnotherOpaqueTenantCannotReadRefreshOrRevokeTheOriginalContext() {
        var f = new Fixture();
        var created = f.create(PARTY_A, f.actorA);
        var otherTenant = f.principal("https://issuer.example/realms/workforce", " tenant, /β ");
        StepVerifier.create(f.in(f.manager.getSessionBySessionId(created.getSessionId()), otherTenant)).verifyComplete();
        StepVerifier.create(f.in(f.manager.refreshSession(created.getSessionId()), otherTenant)).verifyComplete();
        f.in(f.manager.invalidateSessionsByPartyId(PARTY_A), otherTenant).block();
        StepVerifier.create(f.in(f.manager.invalidateSession(created.getSessionId()), otherTenant))
                .expectError(IllegalStateException.class).verify();
        assertThat(f.in(f.manager.getSessionBySessionId(created.getSessionId()), f.actorA).block()).isNotNull();
    }

    @Test
    void equalTenantStringsFromDifferentIssuersDoNotShareSessions() {
        var f = new Fixture();
        var created = f.create(PARTY_A, f.actorA);
        var otherIssuer = f.principal("https://other-issuer.example/realms/workforce", " tenant, /α ");
        StepVerifier.create(f.in(f.manager.getSessionBySessionId(created.getSessionId()), otherIssuer)).verifyComplete();
        assertThat(f.in(f.manager.getSessionByPartyId(PARTY_A), f.actorA).block()).isNotNull();
    }

    @Test
    void partyInvalidationLeavesOtherPartiesAndOtherTenantsUntouched() {
        var f = new Fixture();
        var a1 = f.create(PARTY_A, f.actorA);
        var a2 = f.create(PARTY_A, f.actorA);
        var b = f.create(PARTY_B, f.actorA);
        var otherTenant = f.principal("https://issuer.example/realms/workforce", "other-tenant");
        var other = f.create(PARTY_A, otherTenant);

        f.in(f.manager.invalidateSessionsByPartyId(PARTY_A), f.actorA).block();

        StepVerifier.create(f.in(f.manager.getSessionBySessionId(a1.getSessionId()), f.actorA)).verifyComplete();
        StepVerifier.create(f.in(f.manager.getSessionBySessionId(a2.getSessionId()), f.actorA)).verifyComplete();
        StepVerifier.create(f.in(f.manager.getSessionByPartyId(PARTY_A), f.actorA)).verifyComplete();
        assertThat(f.in(f.manager.getSessionBySessionId(b.getSessionId()), f.actorA).block()).isNotNull();
        assertThat(f.in(f.manager.getSessionBySessionId(other.getSessionId()), otherTenant).block()).isNotNull();
        assertThat(f.cache.clearCalls.get()).isZero();
    }

    @Test
    void individualRevocationCannotBeReversedByReadRefreshOrValidation() {
        var f = new Fixture();
        var created = f.create(PARTY_A, f.actorA);
        f.in(f.manager.invalidateSession(created.getSessionId()), f.actorA).block();

        StepVerifier.create(f.in(f.manager.getSessionBySessionId(created.getSessionId()), f.actorA)).verifyComplete();
        StepVerifier.create(f.in(f.manager.refreshSession(created.getSessionId()), f.actorA)).verifyComplete();
        assertThat(f.in(f.manager.isSessionValid(created), f.actorA).block()).isFalse();
        assertThat(f.aggregations.get()).isEqualTo(1);
        assertThat(f.create(PARTY_A, f.actorA).getSessionId()).isNotEqualTo(created.getSessionId());
    }

    @Test
    void expiredContextAndCacheLossNeverTriggerImplicitCreation() {
        var f = new Fixture();
        var created = f.create(PARTY_A, f.actorA);
        f.clock.advance(Duration.ofMinutes(31));
        var freshCredential = f.principal("https://issuer.example/realms/workforce", " tenant, /α ");
        StepVerifier.create(f.in(f.manager.getSessionBySessionId(created.getSessionId()), freshCredential)).verifyComplete();
        StepVerifier.create(f.in(f.manager.refreshSession(created.getSessionId()), freshCredential)).verifyComplete();
        f.cache.values.clear();
        StepVerifier.create(f.in(f.manager.getSessionBySessionId(created.getSessionId()), freshCredential)).verifyComplete();
        assertThat(f.aggregations.get()).isEqualTo(1);
    }

    @Test
    void refreshKeepsOriginalIdentityAndDeadlineWithoutExtendingSessionLifetime() {
        var f = new Fixture();
        var created = f.create(PARTY_A, f.actorA);
        f.clock.advance(Duration.ofMinutes(5));
        var refreshed = f.in(f.manager.refreshSession(created.getSessionId()), f.actorA).block();

        assertThat(refreshed.getSessionId()).isEqualTo(created.getSessionId());
        assertThat(refreshed.getCreatedAt()).isEqualTo(created.getCreatedAt());
        assertThat(refreshed.getExpiresAt()).isEqualTo(created.getExpiresAt());
        assertThat(refreshed.getLastAccessedAt()).isAfter(created.getLastAccessedAt());
        assertThat(f.in(f.manager.getSessionBySessionId(created.getSessionId()), f.actorA).block().getExpiresAt())
                .isEqualTo(created.getExpiresAt());
    }

    @Test
    void creationCannotOutliveTheVerifiedCredentialThatAdmittedIt() {
        var f = new Fixture();
        var shortLived = f.actorA.toBuilder().claims(Map.of("exp", NOW.plusSeconds(60))).build();
        var created = f.create(PARTY_A, shortLived);
        assertThat(created.getExpiresAt()).isEqualTo(java.time.LocalDateTime.of(2026, 10, 31, 12, 1));
        f.clock.advance(Duration.ofSeconds(61));
        StepVerifier.create(f.in(f.manager.getSessionBySessionId(created.getSessionId()), f.actorA)).verifyComplete();
    }

    @Test
    void successfulProviderLoginUsesExplicitCreationInsteadOfReadSideRecreation() {
        var f = new Fixture();
        var auth = f.authenticationService();
        var response = f.in(auth.login(LoginRequest.builder().username("fixture-user").password("fixture-password").build()), f.actorA).block();
        assertThat(response.getPartyId()).isEqualTo(PARTY_A);
        assertThat(f.in(f.manager.getSessionBySessionId(response.getSessionId()), f.actorA).block()).isNotNull();
        assertThat(f.aggregations.get()).isEqualTo(1);
    }

    @Test
    void successfulProviderRefreshCreatesANewContextWithoutRevivingARevokedIdentifier() {
        var f = new Fixture();
        var revoked = f.create(PARTY_A, f.actorA);
        f.in(f.manager.invalidateSession(revoked.getSessionId()), f.actorA).block();
        var response = f.in(f.authenticationService().refresh(RefreshRequest.builder().refreshToken("fixture-refresh").build()), f.actorA).block();
        assertThat(response.getSessionId()).isNotEqualTo(revoked.getSessionId());
        assertThat(f.in(f.manager.getSessionBySessionId(response.getSessionId()), f.actorA).block()).isNotNull();
        StepVerifier.create(f.in(f.manager.getSessionBySessionId(revoked.getSessionId()), f.actorA)).verifyComplete();
    }

    @Test
    void cacheRecordFromAnotherTenantIsRejectedWithoutOverwritingEitherRecord() {
        var f = new Fixture();
        var local = f.create(PARTY_A, f.actorA);
        var foreignPrincipal = f.principal("https://issuer.example/realms/workforce", "foreign");
        var foreign = f.create(PARTY_A, foreignPrincipal);
        var localKey = f.cache.recordKey(local.getSessionId());
        var original = f.cache.values.get(localKey);
        var record = (FireflySessionManagerImpl.CachedSession) original.value();
        var changed = new FireflySessionManagerImpl.CachedSession(record.issuer(), "foreign", record.partyId(),
                record.generation(), record.livePermit(), record.session());
        var corrupt = new TestCache.Value(changed, original.expiresAt());
        f.cache.values.put(localKey, corrupt);

        StepVerifier.create(f.in(f.manager.getSessionBySessionId(local.getSessionId()), f.actorA))
                .expectError(IllegalStateException.class).verify();
        assertThat(f.cache.values.get(localKey)).isSameAs(corrupt);
        assertThat(f.in(f.manager.getSessionBySessionId(foreign.getSessionId()), foreignPrincipal).block()).isNotNull();
    }

    @Test
    void cachedPartyMismatchIsRejectedWithoutRepairingTheForeignRecord() {
        var f = new Fixture();
        var created = f.create(PARTY_A, f.actorA);
        var key = f.cache.recordKey(created.getSessionId());
        var original = f.cache.values.get(key);
        var record = (FireflySessionManagerImpl.CachedSession) original.value();
        var changed = new FireflySessionManagerImpl.CachedSession(record.issuer(), record.platformTenant(), PARTY_B,
                record.generation(), record.livePermit(), record.session());
        var corrupt = new TestCache.Value(changed, original.expiresAt());
        f.cache.values.put(key, corrupt);
        StepVerifier.create(f.in(f.manager.getSessionBySessionId(created.getSessionId()), f.actorA))
                .expectError(IllegalStateException.class).verify();
        assertThat(f.cache.values.get(key)).isSameAs(corrupt);
    }

    @Test
    void revocationDuringRefreshCannotRepublishAnActiveSessionAcrossManagerInstances() {
        var f = new Fixture();
        var created = f.create(PARTY_A, f.actorA);
        var pending = Sinks.<SessionContextDTO>one();
        when(f.aggregation.aggregateSessionContext(PARTY_A)).thenReturn(pending.asMono());
        var peer = new FireflySessionManagerImpl(f.aggregation, new FireflyCacheManager(f.cache), f.contexts, f.clock);

        StepVerifier.create(f.in(f.manager.refreshSession(created.getSessionId()), f.actorA))
                .then(() -> f.in(peer.invalidateSession(created.getSessionId()), f.actorA).block())
                .then(() -> pending.tryEmitValue(f.context(PARTY_A)))
                .expectError(IllegalStateException.class).verify(Duration.ofSeconds(2));
        StepVerifier.create(f.in(peer.getSessionBySessionId(created.getSessionId()), f.actorA)).verifyComplete();
    }

    @Test
    void partyRevocationFencesAnAlreadyStartedExplicitCreation() {
        var f = new Fixture();
        var pending = Sinks.<SessionContextDTO>one();
        when(f.aggregation.aggregateSessionContext(PARTY_A)).thenReturn(pending.asMono());
        var peer = new FireflySessionManagerImpl(f.aggregation, new FireflyCacheManager(f.cache), f.contexts, f.clock);

        StepVerifier.create(f.in(f.manager.createSession(PARTY_A), f.actorA))
                .then(() -> f.in(peer.invalidateSessionsByPartyId(PARTY_A), f.actorA).block())
                .then(() -> pending.tryEmitValue(f.context(PARTY_A)))
                .expectError(IllegalStateException.class).verify(Duration.ofSeconds(2));
        StepVerifier.create(f.in(peer.getSessionByPartyId(PARTY_A), f.actorA)).verifyComplete();
    }

    @Test
    void refreshWriteCompletingAfterRevocationCannotRestoreTheLivenessPermit() {
        var f = new Fixture();
        var created = f.create(PARTY_A, f.actorA);
        var release = Sinks.<Void>one();
        f.cache.nextRecordWrite = release;
        var peer = new FireflySessionManagerImpl(f.aggregation, new FireflyCacheManager(f.cache), f.contexts, f.clock);
        StepVerifier.create(f.in(f.manager.refreshSession(created.getSessionId()), f.actorA))
                .then(() -> assertThat(f.cache.blockedRecordWrites.get()).isEqualTo(1))
                .then(() -> f.in(peer.invalidateSession(created.getSessionId()), f.actorA).block())
                .then(release::tryEmitEmpty)
                .expectError(IllegalStateException.class).verify(Duration.ofSeconds(2));
        StepVerifier.create(f.in(peer.getSessionBySessionId(created.getSessionId()), f.actorA)).verifyComplete();
    }

    @Test
    void missingLivenessReadCannotBeTreatedAsPermissionToReturnCachedData() {
        var f = new Fixture();
        var created = f.create(PARTY_A, f.actorA);
        f.cache.dropLiveReads = true;
        StepVerifier.create(f.in(f.manager.getSessionBySessionId(created.getSessionId()), f.actorA)).verifyComplete();
        assertThat(f.aggregations.get()).isEqualTo(1);
    }

    @Test
    void droppedCacheWritesCannotReturnAnApparentlyCreatedOrRevokedContext() {
        var f = new Fixture();
        f.cache.dropWrites = true;
        StepVerifier.create(f.in(f.manager.createSession(PARTY_A), f.actorA))
                .expectError(IllegalStateException.class).verify();
        f.cache.dropWrites = false;
        var created = f.create(PARTY_A, f.actorA);
        f.cache.dropEvictions = true;
        StepVerifier.create(f.in(f.manager.invalidateSession(created.getSessionId()), f.actorA))
                .expectError(IllegalStateException.class).verify();
    }

    private static final class Fixture {
        final MutableClock clock = new MutableClock();
        final TestCache cache = new TestCache(clock);
        final AtomicInteger aggregations = new AtomicInteger();
        final SessionAggregationServiceImpl aggregation = mock(SessionAggregationServiceImpl.class);
        final SecurityContextPort contexts = () -> Mono.deferContextual(context -> Mono.justOrEmpty(context.<SecurityPrincipal>getOrEmpty(PRINCIPAL)));
        final SecurityPrincipal actorA = principal("https://issuer.example/realms/workforce", " tenant, /α ");
        final FireflySessionManagerImpl manager = new FireflySessionManagerImpl(aggregation, new FireflyCacheManager(cache), contexts, clock);

        Fixture() {
            when(aggregation.aggregateSessionContext(any())).thenAnswer(invocation -> Mono.fromSupplier(() -> {
                aggregations.incrementAndGet();
                return context(invocation.getArgument(0));
            }));
        }

        SessionContextDTO context(UUID party) {
            return SessionContextDTO.builder().partyId(party).activeContracts(List.of()).build();
        }

        SecurityPrincipal principal(String issuer, String tenant) {
            return SecurityPrincipal.builder().subject("opaque/provider-subject").issuer(issuer).tenantId(tenant)
                    .claims(Map.of("exp", clock.instant().plusSeconds(3600))).build();
        }

        <T> Mono<T> in(Mono<T> operation, SecurityPrincipal principal) {
            return operation.contextWrite(context -> context.put(PRINCIPAL, principal));
        }

        SessionContextDTO create(UUID party, SecurityPrincipal principal) {
            return in(manager.createSession(party), principal).block();
        }

        @SuppressWarnings("unchecked")
        AuthenticationServiceImpl authenticationService() {
            var idp = mock(IdpAdapter.class);
            var provider = (ObjectProvider<IdpAdapter>) mock(ObjectProvider.class);
            when(provider.getIfAvailable()).thenReturn(idp);
            var tokens = ResponseEntity.ok(TokenResponse.builder().accessToken("fixture-provider-token").build());
            when(idp.login(any())).thenReturn(Mono.just(tokens));
            when(idp.refresh(any())).thenReturn(Mono.just(tokens));
            when(idp.getUserInfo("fixture-provider-token")).thenReturn(Mono.just(ResponseEntity.ok(
                    UserInfoResponse.builder().sub("provider-subject").preferredUsername("fixture-user").build())));
            var mapping = mock(UserMappingService.class);
            when(mapping.mapToPartyId(any(), any())).thenReturn(Mono.just(PARTY_A));
            var service = new AuthenticationServiceImpl(mock(IdentityPort.class), manager, provider);
            ReflectionTestUtils.setField(service, "userMappingService", mapping);
            return service;
        }
    }

    private static final class MutableClock extends Clock {
        private Instant instant = NOW;
        void advance(Duration elapsed) { instant = instant.plus(elapsed); }
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return instant; }
    }

    private static final class TestCache implements CacheAdapter {
        private record Value(Object value, Instant expiresAt) {}
        final ConcurrentHashMap<Object, Value> values = new ConcurrentHashMap<>();
        final AtomicInteger clearCalls = new AtomicInteger();
        final AtomicInteger blockedRecordWrites = new AtomicInteger();
        final Clock clock;
        volatile boolean dropWrites;
        volatile boolean dropEvictions;
        volatile boolean dropLiveReads;
        volatile Sinks.One<Void> nextRecordWrite;

        TestCache(Clock clock) { this.clock = clock; }
        private Optional<Object> read(Object key) {
            if (dropLiveReads && key.toString().contains(":live:")) return Optional.empty();
            var stored = values.get(key);
            return stored == null || !clock.instant().isBefore(stored.expiresAt()) ? Optional.empty() : Optional.of(stored.value());
        }
        Object recordKey(String id) {
            return values.entrySet().stream().filter(entry -> entry.getValue().value() instanceof FireflySessionManagerImpl.CachedSession session
                    && id.equals(session.session().getSessionId())).map(Map.Entry::getKey).findFirst().orElseThrow();
        }
        @Override @SuppressWarnings("unchecked") public <K,V> Mono<Optional<V>> get(K key) {
            return Mono.fromSupplier(() -> (Optional<V>)(Optional<?>) read(key));
        }
        @Override public <K,V> Mono<Optional<V>> get(K key, Class<V> type) {
            return Mono.fromSupplier(() -> read(key).filter(type::isInstance).map(type::cast));
        }
        @Override public <K,V> Mono<Void> put(K key, V value) { return put(key,value,Duration.ofHours(1)); }
        @Override public <K,V> Mono<Void> put(K key, V value, Duration ttl) {
            return Mono.defer(() -> {
                var gate = nextRecordWrite;
                Mono<Void> write = Mono.fromRunnable(() -> { if (!dropWrites) values.put(key,new Value(value,clock.instant().plus(ttl))); });
                if (value instanceof FireflySessionManagerImpl.CachedSession && gate != null) {
                    nextRecordWrite = null;
                    blockedRecordWrites.incrementAndGet();
                    return gate.asMono().then(write);
                }
                return write;
            });
        }
        @Override public <K,V> Mono<Boolean> putIfAbsent(K key, V value) { return putIfAbsent(key,value,Duration.ofHours(1)); }
        @Override public <K,V> Mono<Boolean> putIfAbsent(K key, V value, Duration ttl) {
            return Mono.fromSupplier(() -> {
                if (dropWrites) return false;
                var inserted = new AtomicBoolean();
                values.compute(key,(ignored,previous) -> {
                    if (previous != null && clock.instant().isBefore(previous.expiresAt())) return previous;
                    inserted.set(true);
                    return new Value(value,clock.instant().plus(ttl));
                });
                return inserted.get();
            });
        }
        @Override public <K> Mono<Boolean> evict(K key) {
            return Mono.fromSupplier(() -> !dropEvictions && values.remove(key) != null);
        }
        @Override public Mono<Void> clear() { return Mono.fromRunnable(() -> { clearCalls.incrementAndGet(); values.clear(); }); }
        @Override public <K> Mono<Boolean> exists(K key) { return Mono.fromSupplier(() -> read(key).isPresent()); }
        @Override @SuppressWarnings("unchecked") public <K> Mono<Set<K>> keys() {
            return Mono.fromSupplier(() -> (Set<K>)(Set<?>) Set.copyOf(values.keySet()));
        }
        @Override public Mono<Long> size() { return Mono.fromSupplier(() -> (long)values.size()); }
        @Override public Mono<CacheStats> getStats() { return Mono.empty(); }
        @Override public CacheType getCacheType() { return CacheType.AUTO; }
        @Override public String getCacheName() { return "test-session-cache"; }
        @Override public boolean isAvailable() { return true; }
        @Override public Mono<CacheHealth> getHealth() { return Mono.empty(); }
        @Override public void close() {}
    }
}
