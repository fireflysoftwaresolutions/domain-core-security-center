# Verified Security Center receiver contract

This source change introduces a strict direct-self receiver profile through the existing published Jafly security ports. It is not a live-provider or production acceptance result. Local Maven resolution, compilation and tests were deliberately not run on the capacity-constrained development host. The shared `firefly-parent`/BOM must supply the approved framework release; no individual framework dependency version is overridden here.

## Trust and default behavior

The web module depends on managed `fireflyframework-security-resource-server`. Its standard remote-JWKS decoder performs signature, exact issuer, intended audience and timestamp validation, and its standard converter projects the signed tenant claim into the generic `SecurityPrincipal`. Security Center adds no JWT crypto, provider SDK verification, Keycloak-specific token parser, or forwarded-proof header.

Startup requires all of:

- `SECURITY_CENTER_TRUSTED_ISSUER`: exact trusted issuer, without normalization or fallback.
- `SECURITY_CENTER_TRUSTED_JWKS_URI`: explicit JWKS URL for that issuer.
- `SECURITY_CENTER_AUDIENCE`: this receiver's intended audience, not another service's token audience.
- `SECURITY_CENTER_POPULATION`: exactly `HUMAN` or `STAFF` for this deployment's approved population/issuer profile.
- `SECURITY_CENTER_ALLOWED_CLIENTS`: mandatory nonempty comma-separated direct-client allowlist, bound to `firefly.security-center.receiver.allowed-clients`. These are operator-approved client identifiers, not names inferred by the service.

`application.yml` configures the same issuer/audience in the receiver guard and resource-server properties, enables the resource server, requires `tenant_id` projection, enables strict policy, and allows RS256. The receiving web configuration refuses inconsistent/absent trust, missing JWKS, optional tenant projection, non-strict policy, public permit matchers, or symmetric/unknown algorithm configuration. The transport profile defaults to `https`: both issuer and JWKS require HTTPS. The sole HTTP exception is explicit `SECURITY_CENTER_RECEIVER_TRANSPORT_PROFILE=isolated-firefly-id-sandbox` (property `firefly.security-center.receiver.transport-profile`). It permits only `id.firefly.test`, `localhost`, `127.0.0.1`, or IPv6 loopback on port **8180**, one of the exact `/realms/sandbox-customers`, `/realms/sandbox-workforce`, `/realms/sandbox-institutions` paths, and the same-origin exact issuer + `/protocol/openid-connect/certs` JWKS URL. Queries, credentials, fragments, another host/port/realm/path, a mixed HTTP/HTTPS origin, or an unknown profile fail. This narrow synthetic exception does not disable signature/issuer/audience/tenant/client/policy validation and must not be promoted to production. Hostnames still require operator-controlled local DNS/routing. The URI check is configuration validation, not certificate or network acceptance.

Only access checks, self identity projection, and session routes can reach controllers after bearer authentication. Every other web route is denied, including legacy `/api/v1/auth/**` credential/token proxies, `/api/v1/users/**` provisioning, conditional `/idp/admin/**` routes, API documentation, and management endpoints. There is no production test/sandbox disable flag. Health detail/component visibility is `never`; management probes must be deployed through a separately reviewed private management boundary instead of making detailed health publicly readable.

The existing legacy authentication controller's direct unit tests do not prove HTTP exposure: its public routes are denied by the real receiver chain. Its token-bearing service responses are not part of this new receiver contract. No bearer/refresh/ID token field is added to `Subject`, `AccessDecision`, or the session DTO contract.

## Direct actor proof

The guard reads `SecurityContextPort.currentPrincipal()` for the current independently verified authentication. A body, username, arbitrary target subject/role, party selector header, session ID, or caller-supplied scope is never a principal source.

For a direct actor it requires:

| Signed profile | Required actor proof | Unsupported mixed proof |
| --- | --- | --- |
| `principal_kind=HUMAN` | Canonical UUID string `party_id` | Any `staff_actor_id` |
| `principal_kind=STAFF` | Canonical UUID string `staff_actor_id` | Any `party_id` |

The principal's issuer must equal the configured issuer and its population must equal the configured population. The opaque subject is preserved; it is never parsed as a UUID or used as a party ID. The opaque projected tenant must be nonblank and exactly equal signed `tenant_id`; no Configuration resource UUID or request header replaces it. The signed intended audience must be present. Signed `client_id` must be a nonblank String exactly present in the configured direct-client allowlist. Missing, numeric, wrong, or whitespace-altered values fail before policy; `azp` and request headers are not fallbacks. The allowlist itself must be explicit and nonempty at startup. Direct-client binding says which interactive client issued this caller proof; it is distinct from a future verified delegating-client relationship and does not enable machine-to-human delegation. `exp` must be a future `Instant`; if `nbf` exists it must be an `Instant` at or before the current time. Untyped numeric/string temporal proof at this layer is refused rather than silently normalized again.

A requested actor is an optional **selector** for the current signed actor only. When present it must exactly equal the canonical signed actor reference. A differently requested actor, absent/mixed proof, expired proof, other issuer, tenant projection mismatch, other population, or `MACHINE` principal is refused before target evaluation.

This implementation does not authenticate machine-to-human delegation or administrative simulation. `ADMINISTER` and `IMPERSONATE` access requests are unavailable by default. A future terminal/service delegation profile needs a genuine verified shared-framework exchange/transport contract with its own audience, delegating client, original human actor and current policy. Neither `client_credentials` nor an invented proof header becomes a human principal. No dormant accept-all delegation extension is shipped.

## Current policy and access decisions

After proof admission the guard invokes the actual `PolicyDecisionPort.authorize(principal, action, resource, context)` for the exact operation/resource. It overwrites context keys `actorId`, `issuer`, `tenantId`, `principalKind`, and `clientId` with the verified actor, issuer, opaque tenant, population and signed direct client. A caller-supplied context value cannot substitute for any of these fields. Only `PERMIT` with no obligations proceeds. `DENY`, `INDETERMINATE`, empty completion, synchronous/asynchronous errors, timeout, and any obligation that this receiver cannot fulfill all deny. Errors expose a fixed refusal, not backend policy details or credentials. The guard checks proof freshness again before returning an admitted actor.

The default `AccessPort` is now `current-policy`, implemented by `CurrentPolicyAccessAdapter`. It is usable by both public controllers and internal callers and never performs an identity-provider lookup of a business actor UUID. Its successful reason code is `CURRENT_POLICY_PERMIT`. For an access request, PDP action is the exact `AccessAction` name and resource is `<AccessResourceType>:<resourceId>`, with context operation `security-center.access.check`.

The public controller also enforces caller admission before invoking **any** configured port, so a custom or explicitly selected legacy adapter cannot use target roles to bypass caller/PDP admission. With the default port this deliberately re-evaluates the same current policy at the port boundary; both decisions must permit. Legacy `sandbox` and `session-grants` adapters remain explicit compatibility/test choices wrapped by `AdmittedAccessRestriction`. Both HTTP and internal `AccessPort` calls must pass the same verified self/client/current-PDP admission before either legacy delegate or its identity lookup can execute. The delegate can then only further restrict; an empty/error delegate result fails closed. Their `IdentityPort.resolve(actorId)` behavior is not verified caller proof and must not be used to turn a party/staff UUID into an opaque IdP subject in the authoritative path.

## Endpoint behavior

| Endpoint | Receiver policy operation/resource | Additional ownership rule |
| --- | --- | --- |
| `POST /api/v1/access/checks` | Requested action and `<resourceType>:<resourceId>` | Body actor must be the signed self actor; configured port can only further restrict |
| `POST /api/v1/identity/subjects` | `identity.subject.read`, `identity:self` | Empty body or exact self actor selector; username/password bodies return 400 |
| `POST /api/v1/sessions` | `session.create` / `session:self`, or `session.read` / selected session | HUMAN self party only; selected missing session returns 404 without creation |
| `GET /api/v1/sessions/{sessionId}` | `session.read`, `session:<sessionId>` | Cached result's party must match signed self party before DTO exposure |
| `GET /api/v1/sessions/party/{partyId}` | `session.read`, `party:<partyId>` | Path party must match signed self party before cache read |
| `DELETE /api/v1/sessions/{sessionId}` | `session.delete`, `session:<sessionId>` | Read admitted cached record and verify owner before invalidation |
| `DELETE /api/v1/sessions/party/{partyId}` | `session.delete`, `party:<partyId>` | Signed self party relation before invalidation |
| `POST /api/v1/sessions/{sessionId}/refresh` | `session.refresh`, `session:<sessionId>` | Read and verify original owner before refresh; returned record owner also checked |
| `GET /api/v1/sessions/{sessionId}/validate` | `session.validate`, `session:<sessionId>` | Owner check before validation; missing record returns false without creation |
| `GET /api/v1/sessions/access-check` | `session.product.access`, `PRODUCT:<productId>` | Signed self party before cached contract/product restriction |
| `GET /api/v1/sessions/permission-check` | Requested `actionType`, `PRODUCT:<productId>`; context operation and requested resource type | Signed self party before cached permission restriction |

Self identity is projected directly from admitted claims and normalized verified authorities. `provider` uses the configured existing `IdentityAdapter` metadata; it is not authentication by that adapter. There is no username-only authentication or `IdentityPort.resolve(partyUUID)` call in this endpoint.

Session operations support HUMAN party ownership only. A staff UUID, even if it happens to equal a party UUID string, cannot claim a party session. Staff-to-party relationship operations require their own approved authoritative relationship/delegation contract. `X-Party-Id` is at most an exact self selector, never authentication. `X-Session-Id` selects an existing context and never authorizes recreation of an unavailable one. Issuer/tenant cache scoping and lifecycle are enforced separately by the session manager; a cached context never grants a caller identity or substitutes for current policy.

## Source tests and qualification

New source tests cover mandatory exact direct-client binding and context overwrite, explicit legacy-port admission before any downstream identity/session call, HTTPS-default/narrow sandbox HTTP URL rejection, guard admission, wrong actor/issuer/tenant/population, absent proof/principal, expired/untyped/future temporal claims, policy errors/empty/indeterminate/obligations, internal current-policy access, controller refusal before target calls, direct identity projection, session owner checks before mutations, selected-missing-session behavior, strict startup configuration, and denied legacy/admin/management routes. Test fixtures explicitly provide a verified-principal port and current-policy decision; they do not add an authorization-bypassing controller constructor. The HTTP-chain test uses a stated decoder fixture to test routing, not as signature-validation evidence.

OpenAPI generation remains a separate test-classpath controller-scanning harness; it does not enable a runtime security disable switch. The scanned access controller declares the producer's explicit `bearerAuth` HTTP bearer/JWT security scheme, and the access/identity/session controllers each declare its `SecurityRequirement` plus 401/403 responses. The schema-generation harness therefore sees the actual bearer contract without importing production receiver configuration. Existing `AutoMockMissingBeansConfig` already supplies the new final guard and adapter metadata dependencies; duplicate test mocks or a runtime security-disable switch were not added.

Legacy `AuthenticationController` and `UserController` now have `@Hidden`: their Java methods/services remain ABI-compatible, while the candidate canonical OpenAPI/next generated SDK intentionally no longer advertises unsupported credential proxies or provisioning operations. This is a candidate producer-surface change, not a claim that a previously published SDK has changed. `ReceiverOpenApiContractTest` exercises the real test-only generation harness and asserts the emitted scheme/requirements and absent legacy paths; it is written but unrun. Genuine producer regeneration and candidate SDK compilation remain pending. No generated OpenAPI file or SDK was hand-edited. Generation, compilation, unit tests, actual JWT/JWKS HTTP admission, deployed policy integration, denied-route probes, real consumer migration and production acceptance remain unperformed pending the approved hosted validation environment and coherent shared-parent/framework artifact availability.


The source qualification fixture may use the approved exact shared-parent source overlay for framework train 26.10.23, but that does not publish or replace released `firefly-parent:26.10.6`, nor authorize a per-repository framework version override. Ordinary released-parent adoption remains independently blocked until coherent artifacts are available. Source session ownership/admission work does not establish cache-backend revocation/fencing capability, live session revocation, distributed execution, or production acceptance.
