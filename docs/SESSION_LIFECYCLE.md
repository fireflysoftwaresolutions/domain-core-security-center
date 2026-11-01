# Application session context lifecycle

Security Center caches ephemeral application context: party information, contracts, products, roles, and metadata aggregated from their owners. A cached context is not proof of authentication, a Keycloak session, an OAuth token, or a business database record. Receiving authentication, party admission, current purpose authorization, and provider logout remain separate responsibilities.

## Verified namespace

Every manager operation that reads or changes a context requires the current principal from Jafly `SecurityContextPort`. Its issuer, subject, and tenant must be nonblank, and its validated `exp` claim must be a future `Instant`. Cache namespace isolation uses the exact issuer and opaque tenant string. Whitespace, punctuation, and Unicode in tenant identifiers are preserved; a tenant is not parsed into a party or Configuration resource UUID.

`SessionContextDTO` keeps its existing wire shape. The internal cache wrapper stores issuer, tenant, party, generation, session identifier, and a random liveness permit. A record whose stored namespace or party differs from the requested scope is rejected without repairing or overwriting the foreign record.

The HTTP receiver must independently authorize the selected party/session before calling the manager. An admitted party UUID does not supply issuer trust or permission. The retained two-argument manager constructor supplies no principal and therefore fails closed; production injection uses the constructor that requires `SecurityContextPort`.

## Creation and lookup

| Operation | Behavior |
| --- | --- |
| `createSession(partyId)` | Explicitly aggregates and creates a new context after caller/party admission. Each creation receives a fresh identifier. |
| `createOrGetSession(exchange)` without `X-Session-Id` | Explicitly creates a context for the admitted `X-Party-Id`. |
| `createOrGetSession(exchange)` with `X-Session-Id` | Looks up that existing context and requires its party to match. Missing, expired, or invalidated identifiers are never creation requests. |
| `getSessionBySessionId` | Returns an existing live context in the verified namespace, or empty. It does not reconstruct a session from the identifier. |
| `getSessionByPartyId` | Looks up the party's selected previously created context, or empty. It never aggregates on a cache miss. |
| `refreshSession` | Reaggregates an existing live context and preserves its identifier, creation time, and original expiration. It does not revive a missing or revoked context or extend its lifetime. |
| `isSessionValid` | Requires a matching live cache entry; an old detached DTO does not remain valid after revocation. |

Successful provider login and refresh call the explicit creation method. They still require an approved verified namespace and party admission from the receiving flow; provider success alone does not manufacture that scope. Custom manager implementations inherit a failing default creation method until they implement it explicitly.

Context lifetime is at most 30 minutes, bounded further by the admitting credential and the current party generation deadline. Timestamps use UTC. Looking up or refreshing a context does not renew its expiration. Cache loss therefore requires a new explicit creation under fresh admission, not reconstruction during a read.

The session identifier remains a string and must be treated as opaque. It contains a random component, and is never used as evidence that the caller logged in. Legacy unscoped cache entries are not imported into a verified namespace; they expire under the existing cache policy. No business or provider data is deleted by this format transition.

## Scoped invalidation and concurrent operations

Invalidating one session removes its immutable positive liveness permit. Refresh only updates context data and never recreates that permit. Reads and publication require the permit to remain present and unchanged. A refresh whose data write completes after invalidation cannot make the session live again.

Invalidating all sessions for a party rotates only that party's generation inside the verified issuer/tenant namespace. Older generations become inaccessible, including writes already in flight. Other parties, tenants, and issuers remain untouched. Old context data expires within its original deadline; the manager does not clear the shared session cache. Generation metadata has a bounded one-hour TTL, and expired generation state never causes read-side creation.

Cache writes are read back, and creation uses the cache provider's `putIfAbsent` contract. Per-session invalidation requires a successful eviction result; a false or unknown result is reported as unavailable instead of claiming revocation. This matters because `FireflyCacheManager` maps some provider errors to empty reads or false results. Absence of a revocation marker is never treated as permission: live context access requires positive generation, liveness, and matching record state.

These fences use shared-cache state rather than JVM locks. They require coherent per-key reads/writes, atomic `putIfAbsent`, and honest eviction results from the active provider. They do not provide a multi-key database transaction, durable identity-provider revocation, or consistency across stale cache restore, partition, or failover. A deployment that requires those guarantees must qualify its real provider and failover policy separately; a fallback cache or restored snapshot cannot be treated as durable authentication authority.

## Verification boundaries

`FireflySessionManagerImplTest` adds unit regression scenarios for namespace and party isolation, explicit creation, lookup misses, expiration, refresh deadlines, invalidation, dropped cache operations, and deterministic two-manager interleavings. It uses a shared in-memory cache adapter and mocked owner/provider I/O. These scenarios do not qualify Redis serialization, a deployed receiving security chain, live Keycloak, or business owner integration.

Repository commands are `mvn test` for the test suite and `mvn verify` for the broader build. The focused reactor command is `mvn -pl domain-core-security-center-core -am -Dtest=FireflySessionManagerImplTest -Dsurefire.failIfNoSpecifiedTests=false test`. Run these only in an approved resource window with the genuine parent/dependency train. No local compilation or test execution was performed for this source candidate because the workspace was below the agreed disk floor.
