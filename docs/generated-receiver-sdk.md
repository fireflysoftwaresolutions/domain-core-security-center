# Generate the direct receiver SDK from its original producer

The receiver is a Domain service. Experience clients call Domain; they do not bypass it to call Core. Its visible operations require the direct receiver bearer contract described in [the receiver contract](security-receiver-contract.md). A staff identity does not become a party identity, and the SDK does not create delegation or bypass current policy admission.

The original producer already declares the `bearerAuth` HTTP bearer scheme. The checked-in SDK input predates those receiver changes. It must not be repaired by adding authentication to a generated specification or editing generated Java. The actual SDK input is `domain-core-security-center-sdk/src/main/resources/openapi.yml`; the older `api-spec/openapi.yml` file is not selected by the SDK generator POM.

## Source qualification pipeline

The existing isolated source-parent fixture runs the original producer through the real `OpenApiGenApplication` and Springdoc. The producer test retains its exact JSON response before contract assertions. The inherited `generate-openapi` profile starts that producer and writes its YAML response to the SDK input during the web module's integration-test phase. The official OpenAPI Generator then generates the SDK in its subsequent reactor module. The identity operation explicitly retains the existing `resolveSubject` client operation name.

The SDK tests require the selected YAML paths and security scheme to match the captured original producer JSON. They also require actual generated bearer support and overlapping caller isolation through the generated identity operation. Each caller owns a fresh generated `ApiClient` and its generated authentication object. The transport fixture supplies no Authorization header itself. This checks generated credential attachment without opening a connection or claiming JWT, receiver, or provider acceptance.

The post-build verifier requires all named producer and SDK tests to have executed once without failures, errors or skips. It records hashes for the original JSON, actual selected YAML, generated API/authentication source and packaged SDK, and requires the corresponding classes in the SDK JAR. The hosted workflow retains these outputs and test reports; summary counts alone are not generated-contract evidence. The Python parser controls use deliberately synthetic XML and are not SDK or Java execution evidence.

## Review and adoption boundary

The bounded hosted source-parent qualification passed the original-producer negative regression, whole-reactor verification and all required producer and generated SDK tests. Retained generated sources confirm `Mono<Subject>` and `Mono<AccessDecision>`; the client tests decoded both caller-specific subjects and allowed/denied access decisions. The retained SDK JAR contains the exact producer-selected YAML input. The checked-in specifications stay unchanged in this source candidate. A later canonical update must use the retained original producer output, followed by official generation and compilation; it must not hand-edit the spec or SDK.

The fixture uses the qualified framework `26.10.23` source-parent alignment. This is not a new released service parent, SDK publication, terminal integration, machine-to-human delegation, session revocation or production acceptance. Terminal adoption must preserve a separate client per caller and demonstrate credential isolation. The receiver still owns issuer, audience, signed client, population, opaque subject/tenant, actor binding and current policy checks. HUMAN-only session operations remain unavailable to staff callers.


## Typed success-body correction

The first retained original-producer/SDK qualification established bearer authentication and per-caller credential isolation but exposed another contract gap during artifact inspection: both generated operations returned `Mono<Void>`, because their producer metadata declared error responses without a typed success response. That success receipt is limited to its actual authentication/input checks and is not proof of usable typed DTOs.

The successor adds explicit JSON200 metadata for `Subject` and `AccessDecision` without changing either controller body or transport behavior. Its generated-client tests must decode both per-caller Subject bodies and allowed/denied AccessDecision bodies using the generated client's real codec strategy through a supported in-process Spring connector. Response type inference or `.then()` completion alone cannot satisfy this check. These successor Java and generation tests passed in the bounded hosted qualification, including the two overlapping callers and typed response bodies. No generated specification or SDK source is hand-edited.
