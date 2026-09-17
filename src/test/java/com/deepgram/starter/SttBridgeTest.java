package com.deepgram.starter;

import okio.ByteString;
import com.deepgram.core.DeepgramHttpException;
import com.deepgram.resources.listen.v1.websocket.V1WebSocketClient;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.javalin.websocket.WsContext;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.mockito.ArgumentCaptor;
import org.eclipse.jetty.websocket.api.RemoteEndpoint;
import org.eclipse.jetty.websocket.api.Session;
import org.eclipse.jetty.websocket.api.WriteCallback;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
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

    @Test
    void directSdkErrorsCloseOnlyAfterTheErrorFrameIsWritten() throws Exception {
        Session session = mock(Session.class);
        RemoteEndpoint remote = mock(RemoteEndpoint.class);
        when(session.isOpen()).thenReturn(true);
        when(session.getRemote()).thenReturn(remote);
        WsContext clientCtx = spy(new WsContext("/api/live-transcription", session) {});
        V1WebSocketClient deepgram = mock(V1WebSocketClient.class);
        App.SttBridge bridge = new App.SttBridge(deepgram, "direct-sdk-error", () -> {});
        Map<String, WsContext> activeConnections = new HashMap<>();
        activeConnections.put("direct-sdk-error", clientCtx);
        ArgumentCaptor<WriteCallback> callback = ArgumentCaptor.forClass(WriteCallback.class);
        InOrder order = inOrder(remote, clientCtx);

        App.reportConnectionFailure(clientCtx, bridge, "direct-sdk-error",
            App.safeDeepgramConnectionError(new DeepgramHttpException("secret", 503, null)),
            new AtomicBoolean(), activeConnections);

        order.verify(remote).sendString(eq(App.clientErrorFrame(
            "Deepgram rejected the connection (HTTP 503)", "CONNECTION_FAILED")), callback.capture());
        verify(clientCtx, never()).closeSession(1011, "Deepgram connection lost");

        callback.getValue().writeSuccess();

        order.verify(clientCtx).closeSession(1011, "Deepgram connection lost");
        verify(deepgram).disconnect();
        assertFalse(activeConnections.containsKey("direct-sdk-error"));
    }

    @Test
    void failedConnectClosesOnlyAfterTheErrorFrameWriteFails() throws Exception {
        Session session = mock(Session.class);
        RemoteEndpoint remote = mock(RemoteEndpoint.class);
        when(session.isOpen()).thenReturn(true);
        when(session.getRemote()).thenReturn(remote);
        WsContext clientCtx = spy(new WsContext("/api/live-transcription", session) {});
        V1WebSocketClient deepgram = mock(V1WebSocketClient.class);
        App.SttBridge bridge = new App.SttBridge(deepgram, "failed-connect", () -> {});
        Map<String, WsContext> activeConnections = new HashMap<>();
        activeConnections.put("failed-connect", clientCtx);
        ArgumentCaptor<WriteCallback> callback = ArgumentCaptor.forClass(WriteCallback.class);
        InOrder order = inOrder(remote, clientCtx);

        App.reportConnectionFailure(clientCtx, bridge, "failed-connect",
            App.safeDeepgramConnectionError(new RuntimeException("secret")),
            new AtomicBoolean(), activeConnections);

        order.verify(remote).sendString(eq(App.clientErrorFrame(
            "Failed to connect to Deepgram", "CONNECTION_FAILED")), callback.capture());
        verify(clientCtx, never()).closeSession(1011, "Deepgram connection lost");

        callback.getValue().writeFailed(new RuntimeException("write failed"));

        order.verify(clientCtx).closeSession(1011, "Deepgram connection lost");
        verify(deepgram).disconnect();
        assertFalse(activeConnections.containsKey("failed-connect"));
    }
}
