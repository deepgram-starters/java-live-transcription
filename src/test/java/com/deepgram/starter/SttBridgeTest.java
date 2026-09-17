package com.deepgram.starter;

import okio.ByteString;
import com.deepgram.core.ClientOptions;
import com.deepgram.core.DeepgramHttpException;
import com.deepgram.core.Environment;
import com.deepgram.core.ReconnectingWebSocketListener;
import com.deepgram.types.ListenV1Model;
import com.deepgram.resources.listen.v1.websocket.V1ConnectOptions;
import com.deepgram.resources.listen.v1.websocket.V1WebSocketClient;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.javalin.websocket.WsContext;
import okhttp3.OkHttpClient;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InOrder;
import org.mockito.ArgumentCaptor;
import org.eclipse.jetty.websocket.api.RemoteEndpoint;
import org.eclipse.jetty.websocket.api.Session;
import org.eclipse.jetty.websocket.api.WriteCallback;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SttBridgeTest {

    @Test
    void capsFramesQueuedBeforeConnection() {
        AtomicBoolean overloaded = new AtomicBoolean();
        App.SttBridge bridge = new App.SttBridge(null, "test", () -> overloaded.set(true));

        for (int index = 0; index <= 128; index++) {
            bridge.sendAudio(ByteString.of(new byte[] {1}));
        }

        assertTrue(overloaded.get());
        assertFalse(bridge.sendControl("KeepAlive"));
    }

    @Test
    void capsBytesQueuedBeforeConnection() {
        AtomicBoolean overloaded = new AtomicBoolean();
        App.SttBridge bridge = new App.SttBridge(null, "test", () -> overloaded.set(true));

        bridge.sendAudio(ByteString.of(new byte[512 * 1024]));
        bridge.sendAudio(ByteString.of(new byte[] {1}));

        assertTrue(overloaded.get());
        assertFalse(bridge.sendControl("Finalize"));
    }

    @Test
    void acceptsDocumentedControlsBeforeConnection() {
        App.SttBridge bridge = new App.SttBridge(null, "test", () -> {});

        assertTrue(bridge.sendControl("KeepAlive"));
        assertTrue(bridge.sendControl("Finalize"));
        assertTrue(bridge.sendControl("CloseStream"));
        assertFalse(bridge.sendControl("Unknown"));
    }

    @Test
    void flushesQueuedFramesThroughTheSdkInArrivalOrder() {
        V1WebSocketClient deepgram = mock(V1WebSocketClient.class);
        ByteString audio = ByteString.of(new byte[] {1, 2, 3});
        App.SttBridge bridge = new App.SttBridge(deepgram, "test", () -> {});

        bridge.sendAudio(audio);
        bridge.sendControl("KeepAlive");
        bridge.sendControl("Finalize");
        bridge.sendControl("CloseStream");
        bridge.markReady();

        InOrder order = inOrder(deepgram);
        order.verify(deepgram).sendMedia(audio);
        order.verify(deepgram).sendKeepAlive(any());
        order.verify(deepgram).sendFinalize(any());
        order.verify(deepgram).sendCloseStream(any());
    }

    @Test
    void clientErrorsIncludeTheFrontendDescription() throws Exception {
        var frame = new ObjectMapper().readTree(App.clientErrorFrame("Invalid JSON", "INVALID_JSON"));

        assertEquals("Error", frame.path("type").asText());
        assertEquals("Invalid JSON", frame.path("description").asText());
        assertEquals("Invalid JSON", frame.path("error").path("message").asText());
    }

    @Test
    void authenticationFailuresSendASanitizedBrowserErrorFrame() throws Exception {
        String secret = "test-connect-secret";
        var error = new RuntimeException(new DeepgramHttpException("Authorization: Token " + secret, 401, null));
        var frame = new ObjectMapper().readTree(App.clientErrorFrame(
            App.safeDeepgramConnectionError(error), "CONNECTION_FAILED"));

        assertEquals("Error", frame.path("type").asText());
        assertEquals("Deepgram rejected the connection (HTTP 401)", frame.path("description").asText());
        assertEquals("CONNECTION_FAILED", frame.path("error").path("code").asText());
        assertFalse(frame.toString().contains(secret));
        assertFalse(frame.toString().contains("Authorization"));
    }

    @Test
    void connectionFailuresUseAGenericFallback() {
        assertEquals("Failed to connect to Deepgram", App.safeDeepgramConnectionError(new RuntimeException("secret")));
    }

    @Test
    void connectionFailuresOnlyExposeValidHttpStatuses() {
        assertEquals("Deepgram rejected the connection (HTTP 100)",
            App.safeDeepgramConnectionError(new DeepgramHttpException("secret", 100, null)));
        assertEquals("Deepgram rejected the connection (HTTP 599)",
            App.safeDeepgramConnectionError(new DeepgramHttpException("secret", 599, null)));
        assertEquals("Failed to connect to Deepgram",
            App.safeDeepgramConnectionError(new DeepgramHttpException("secret", 99, null)));
        assertEquals("Failed to connect to Deepgram",
            App.safeDeepgramConnectionError(new DeepgramHttpException("secret", 600, null)));
    }

    @Test
    void nestedInvalidHttpStatusUsesGenericFallback() {
        String secret = "nested-sdk-secret";

        assertEquals("Failed to connect to Deepgram", App.safeDeepgramConnectionError(
            new RuntimeException(new DeepgramHttpException("Authorization: Token " + secret, 0, null))));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    @SuppressWarnings("unchecked")
    void registeredDeepgramErrorHandlerQueuesErrorBeforeClosing(boolean writeSucceeds) throws Exception {
        FailureFixture fixture = failureFixture("direct-sdk-error");
        CompletableFuture<Void> connection = new CompletableFuture<>();
        V1ConnectOptions options = mock(V1ConnectOptions.class);
        when(fixture.deepgram().connect(options)).thenReturn(connection);

        App.connectWithFailureReporting(fixture.deepgram(), options, fixture.clientCtx(), fixture.bridge(),
            fixture.connectionId(), new App.HandshakeStatus(), new AtomicBoolean(), fixture.activeConnections());

        ArgumentCaptor<Consumer<Exception>> errorHandler = ArgumentCaptor.forClass(Consumer.class);
        verify(fixture.deepgram()).onError(errorHandler.capture());
        errorHandler.getValue().accept(new DeepgramHttpException("secret", 503, null));

        assertErrorQueuedBeforeClose(fixture, "Deepgram rejected the connection (HTTP 503)", writeSucceeds);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void failedConnectCompletionQueuesErrorBeforeClosing(boolean writeSucceeds) throws Exception {
        FailureFixture fixture = failureFixture("failed-connect");
        CompletableFuture<Void> connection = new CompletableFuture<>();
        V1ConnectOptions options = mock(V1ConnectOptions.class);
        when(fixture.deepgram().connect(options)).thenReturn(connection);

        App.connectWithFailureReporting(fixture.deepgram(), options, fixture.clientCtx(), fixture.bridge(),
            fixture.connectionId(), new App.HandshakeStatus(), new AtomicBoolean(), fixture.activeConnections());
        connection.completeExceptionally(new RuntimeException("secret"));

        assertErrorQueuedBeforeClose(fixture, "Failed to connect to Deepgram", writeSucceeds);
    }

    @Test
    void invalidKeyHandshakeReportsCapturedStatusBeforeClosing() throws Exception {
        String apiKey = "deterministic-invalid-key";
        try (MockWebServer server = new MockWebServer()) {
            server.enqueue(new MockResponse().setResponseCode(401).setBody("unauthorized"));
            server.start();

            App.HandshakeStatus handshakeStatus = new App.HandshakeStatus();
            V1WebSocketClient deepgram = new V1WebSocketClient(ClientOptions.builder()
                .environment(Environment.custom().production(server.url("/").toString()).build())
                .addHeader("Authorization", "Token " + apiKey)
                .webSocketFactory(new App.StatusCapturingWebSocketFactory(new OkHttpClient(), handshakeStatus))
                .build());
            deepgram.reconnectOptions(ReconnectingWebSocketListener.ReconnectOptions.builder()
                .maxRetries(0)
                .build());
            FailureFixture fixture = failureFixture("invalid-key-handshake");
            V1ConnectOptions options = V1ConnectOptions.builder()
                .model(ListenV1Model.valueOf("nova-3"))
                .build();

            App.connectWithFailureReporting(deepgram, options, fixture.clientCtx(), fixture.bridge(),
                fixture.connectionId(), handshakeStatus, new AtomicBoolean(), fixture.activeConnections());

            ArgumentCaptor<String> frameCaptor = ArgumentCaptor.forClass(String.class);
            ArgumentCaptor<WriteCallback> callbackCaptor = ArgumentCaptor.forClass(WriteCallback.class);
            verify(fixture.remote(), timeout(5_000)).sendString(frameCaptor.capture(), callbackCaptor.capture());

            var frame = new ObjectMapper().readTree(frameCaptor.getValue());
            assertEquals("Error", frame.path("type").asText());
            assertEquals("Deepgram rejected the connection (HTTP 401)", frame.path("description").asText());
            assertEquals("CONNECTION_FAILED", frame.path("error").path("code").asText());
            assertFalse(frameCaptor.getValue().contains(apiKey));
            assertFalse(frameCaptor.getValue().contains("Authorization"));
            verify(fixture.clientCtx(), never()).closeSession(1011, "Deepgram connection lost");

            callbackCaptor.getValue().writeSuccess();

            verify(fixture.clientCtx(), timeout(5_000)).closeSession(1011, "Deepgram connection lost");
            assertEquals("Token " + apiKey, server.takeRequest(5, TimeUnit.SECONDS).getHeader("Authorization"));
        }
    }

    private static FailureFixture failureFixture(String connectionId) {
        Session session = mock(Session.class);
        RemoteEndpoint remote = mock(RemoteEndpoint.class);
        when(session.isOpen()).thenReturn(true);
        when(session.getRemote()).thenReturn(remote);
        WsContext clientCtx = spy(new WsContext("/api/live-transcription", session) {});
        V1WebSocketClient deepgram = mock(V1WebSocketClient.class);
        App.SttBridge bridge = new App.SttBridge(deepgram, connectionId, () -> {});
        Map<String, WsContext> activeConnections = new HashMap<>();
        activeConnections.put(connectionId, clientCtx);
        return new FailureFixture(connectionId, clientCtx, remote, deepgram, bridge, activeConnections);
    }

    private static void assertErrorQueuedBeforeClose(
        FailureFixture fixture,
        String description,
        boolean writeSucceeds
    ) throws Exception {
        ArgumentCaptor<WriteCallback> callback = ArgumentCaptor.forClass(WriteCallback.class);
        InOrder order = inOrder(fixture.remote(), fixture.clientCtx());

        order.verify(fixture.remote()).sendString(eq(App.clientErrorFrame(description, "CONNECTION_FAILED")), callback.capture());
        verify(fixture.clientCtx(), never()).closeSession(1011, "Deepgram connection lost");

        if (writeSucceeds) {
            callback.getValue().writeSuccess();
        } else {
            callback.getValue().writeFailed(new RuntimeException("write failed"));
        }

        order.verify(fixture.clientCtx()).closeSession(1011, "Deepgram connection lost");
        verify(fixture.deepgram()).disconnect();
        assertFalse(fixture.activeConnections().containsKey(fixture.connectionId()));
    }

    private record FailureFixture(
        String connectionId,
        WsContext clientCtx,
        RemoteEndpoint remote,
        V1WebSocketClient deepgram,
        App.SttBridge bridge,
        Map<String, WsContext> activeConnections
    ) {}
}
