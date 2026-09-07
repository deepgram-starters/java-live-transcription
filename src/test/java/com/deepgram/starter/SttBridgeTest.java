package com.deepgram.starter;

import okio.ByteString;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
    void acceptsDocumentedControlsBeforeConnection() {
        App.SttBridge bridge = new App.SttBridge(null, "test", () -> {});

        assertTrue(bridge.sendControl("KeepAlive"));
        assertTrue(bridge.sendControl("Finalize"));
        assertTrue(bridge.sendControl("CloseStream"));
        assertFalse(bridge.sendControl("Unknown"));
    }
}
