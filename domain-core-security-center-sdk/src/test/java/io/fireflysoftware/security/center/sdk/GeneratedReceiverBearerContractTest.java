package io.fireflysoftware.security.center.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import io.fireflysoftware.security.center.sdk.api.AccessControllerApi;
import io.fireflysoftware.security.center.sdk.api.IdentityControllerApi;
import io.fireflysoftware.security.center.sdk.invoker.ApiClient;
import io.fireflysoftware.security.center.sdk.invoker.auth.HttpBearerAuth;
import io.fireflysoftware.security.center.sdk.model.AccessRequest;
import io.fireflysoftware.security.center.sdk.model.IdentityRequest;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.client.reactive.ClientHttpConnector;
import org.springframework.http.client.reactive.ClientHttpResponse;
import org.springframework.mock.http.client.reactive.MockClientHttpRequest;
import org.springframework.mock.http.client.reactive.MockClientHttpResponse;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Sinks;
import static org.junit.jupiter.api.Assertions.*;

class GeneratedReceiverBearerContractTest {
    @Test
    void generatorInputMatchesTheOriginalProducerBearerOperations() throws Exception {
        JsonNode original = new ObjectMapper().readTree(Path.of("..", "domain-core-security-center-web",
                "target", "receiver-openapi.json").toFile());
        JsonNode selected = new ObjectMapper(new YAMLFactory()).readTree(
                Path.of("src", "main", "resources", "openapi.yml").toFile());
        assertEquals(original.path("components").path("securitySchemes"),
                selected.path("components").path("securitySchemes"));
        assertEquals(original.path("paths"), selected.path("paths"));
        assertEquals("http", selected.at("/components/securitySchemes/bearerAuth/type").asText());
        assertEquals("bearer", selected.at("/components/securitySchemes/bearerAuth/scheme").asText());
        assertEquals("resolveSubject", selected.path("paths").path("/api/v1/identity/subjects")
                .path("post").path("operationId").asText());
        for (var entry : Map.of("/api/v1/identity/subjects", "Subject",
                "/api/v1/access/checks", "AccessDecision").entrySet()) {
            assertEquals("#/components/schemas/" + entry.getValue(), selected.path("paths").path(entry.getKey())
                    .path("post").path("responses").path("200").path("content").path("application/json")
                    .path("schema").path("$ref").asText());
        }
    }

    @Test
    void generatedAuthenticationIsOwnedByEachCallerClient() {
        ApiClient first = new ApiClient();
        ApiClient second = new ApiClient();
        HttpBearerAuth firstAuth = assertInstanceOf(HttpBearerAuth.class, first.getAuthentication("bearerAuth"));
        HttpBearerAuth secondAuth = assertInstanceOf(HttpBearerAuth.class, second.getAuthentication("bearerAuth"));
        assertNotSame(firstAuth, secondAuth);
        firstAuth.setBearerToken("synthetic-staff-one");
        assertNull(secondAuth.getBearerToken());
    }

    @Test
    void twoOverlappingStaffCallsUseTheirOwnGeneratedBearerAuthentication() {
        Map<String, List<String>> headers = new ConcurrentHashMap<>();
        AtomicInteger arrivals = new AtomicInteger();
        Sinks.Empty<Void> bothEntered = Sinks.empty();
        WebClient transport = transport(request -> {
            String caller = request.getURI().getHost();
            assertNull(headers.putIfAbsent(caller, List.copyOf(request.getHeaders().getOrEmpty(HttpHeaders.AUTHORIZATION))));
            if (arrivals.incrementAndGet() == 2) bothEntered.tryEmitEmpty();
            String actor = caller.equals("staff-one.invalid")
                    ? "11111111-1111-4111-8111-111111111111" : "22222222-2222-4222-8222-222222222222";
            return bothEntered.asMono().thenReturn(json("{\"actorId\":\"" + actor + "\",\"roles\":[]}"));
        });
        ApiClient first = new ApiClient(transport).setBasePath("https://staff-one.invalid");
        ApiClient second = new ApiClient(transport).setBasePath("https://staff-two.invalid");
        first.setBearerToken("synthetic-staff-one");
        second.setBearerToken("synthetic-staff-two");
        var subjects = Mono.zip(new IdentityControllerApi(first).resolveSubject(new IdentityRequest(), null),
                new IdentityControllerApi(second).resolveSubject(new IdentityRequest(), null)).block(Duration.ofSeconds(5));
        assertNotNull(subjects);
        assertEquals("11111111-1111-4111-8111-111111111111", subjects.getT1().getActorId());
        assertEquals("22222222-2222-4222-8222-222222222222", subjects.getT2().getActorId());
        assertEquals(Map.of("staff-one.invalid", List.of("Bearer synthetic-staff-one"),
                "staff-two.invalid", List.of("Bearer synthetic-staff-two")), headers);
        assertEquals(2, arrivals.get());
    }

    @Test
    void generatedAccessDecisionDecodesBothAllowedAndDeniedBodies() {
        AtomicInteger calls = new AtomicInteger();
        WebClient transport = transport(request -> {
            assertEquals(List.of("Bearer synthetic-staff"), request.getHeaders().getOrEmpty(HttpHeaders.AUTHORIZATION));
            boolean allowed = calls.getAndIncrement() == 0;
            return Mono.just(json("{\"allowed\":" + allowed + ",\"reasonCode\":\"synthetic-decision\"}"));
        });
        ApiClient client = new ApiClient(transport).setBasePath("https://staff.invalid");
        client.setBearerToken("synthetic-staff");
        var api = new AccessControllerApi(client);
        var request = new AccessRequest().actorId("11111111-1111-4111-8111-111111111111")
                .action(AccessRequest.ActionEnum.READ).resourceType(AccessRequest.ResourceTypeEnum.ACCOUNT)
                .resourceId("22222222-2222-4222-8222-222222222222");
        var allowed = api.decideAccess(request, null).block(Duration.ofSeconds(5));
        var denied = api.decideAccess(request, null).block(Duration.ofSeconds(5));
        assertNotNull(allowed);assertTrue(allowed.getAllowed());assertEquals("synthetic-decision", allowed.getReasonCode());
        assertNotNull(denied);assertFalse(denied.getAllowed());assertEquals("synthetic-decision", denied.getReasonCode());
        assertEquals(2, calls.get());
    }

    private static WebClient transport(Function<MockClientHttpRequest, Mono<MockClientHttpResponse>> exchange) {
        ClientHttpConnector connector = (method, uri, callback) -> {
            MockClientHttpRequest request = new MockClientHttpRequest(method, uri);
            return callback.apply(request).then(Mono.<ClientHttpResponse>defer(() -> exchange.apply(request)));
        };
        return ApiClient.buildWebClientBuilder().clientConnector(connector).build();
    }

    private static MockClientHttpResponse json(String body) {
        MockClientHttpResponse response = new MockClientHttpResponse(HttpStatus.OK);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        response.setBody(body);
        return response;
    }
}
