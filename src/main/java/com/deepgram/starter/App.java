/**
 * Java Live Transcription Starter - Backend Server
 *
 * A WebSocket bridge server that forwards audio and transcription messages
 * between browser clients and Deepgram's Live Speech-to-Text API. The Deepgram
 * side is handled by the official Deepgram Java SDK
 * (`client.listen().v1().v1WebSocket()`), which manages the connection, auth,
 * and message framing.
 *
 * Key Features:
 * - WebSocket bridge: /api/live-transcription -> Deepgram Live STT (via SDK)
 * - Bidirectional forwarding (binary audio in, JSON results out)
 * - JWT session auth via Sec-WebSocket-Protocol subprotocol
 * - Metadata endpoint: GET /api/metadata
 * - CORS enabled for frontend communication
 * - Graceful shutdown with connection tracking
 *
 * The SDK's typed result/metadata objects serialize to the exact Deepgram wire
 * JSON (`type`, `channel`, `is_final`, `speech_final`, ...), so the browser
 * frontend receives the same messages as before and needs no changes.
 *
 * Routes:
 *   GET  /api/session              - Issue JWT session token
 *   GET  /api/metadata             - Project metadata from deepgram.toml
 *   WS   /api/live-transcription   - WebSocket bridge to Deepgram STT (auth required)
 *   GET  /health                   - Health check
 */

package com.deepgram.starter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.deepgram.DeepgramClient;
import com.deepgram.resources.listen.v1.types.ListenV1CloseStream;
import com.deepgram.resources.listen.v1.types.ListenV1CloseStreamType;
import com.deepgram.resources.listen.v1.websocket.V1ConnectOptions;
import com.deepgram.resources.listen.v1.websocket.V1WebSocketClient;
import com.deepgram.types.ListenV1Channels;
import com.deepgram.types.ListenV1Encoding;
import com.deepgram.types.ListenV1Language;
import com.deepgram.types.ListenV1Model;
import com.deepgram.types.ListenV1SampleRate;
import com.deepgram.types.ListenV1SmartFormat;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.toml.TomlMapper;
import io.github.cdimascio.dotenv.Dotenv;
import io.javalin.Javalin;
import io.javalin.websocket.WsConfig;
import io.javalin.websocket.WsContext;
import okio.ByteString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

// ============================================================================
// MAIN APPLICATION
// ============================================================================

public class App {

    private static final Logger log = LoggerFactory.getLogger(App.class);

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    private static final int JWT_EXPIRY_SECONDS = 3600; // 1 hour

    /** Reserved WebSocket close codes that must not be sent by applications. */
    private static final Set<Integer> RESERVED_CLOSE_CODES = Set.of(1004, 1005, 1006, 1015);

    /** Track active client WebSocket sessions for graceful shutdown. */
    private static final Map<String, WsContext> activeConnections = new ConcurrentHashMap<>();

    /** Shared Deepgram SDK client for outbound connections to Deepgram. */
    private static DeepgramClient deepgram;

    /** JWT signing algorithm. */
    private static Algorithm jwtAlgorithm;

    /** JWT verifier. */
    private static JWTVerifier jwtVerifier;

    /** Jackson ObjectMapper for JSON serialization. */
    private static final ObjectMapper jsonMapper = new ObjectMapper();

    // ========================================================================
    // ENTRY POINT
    // ========================================================================

    public static void main(String[] args) throws Exception {

        // Load .env file (silent if missing)
        Dotenv dotenv = Dotenv.configure().ignoreIfMissing().load();

        // Load configuration from environment
        String deepgramApiKey = dotenv.get("DEEPGRAM_API_KEY");
        if (deepgramApiKey == null || deepgramApiKey.isBlank()) {
            log.error("");
            log.error("ERROR: Deepgram API key not found!");
            log.error("");
            log.error("Please set your API key using one of these methods:");
            log.error("");
            log.error("1. Create a .env file (recommended):");
            log.error("   DEEPGRAM_API_KEY=your_api_key_here");
            log.error("");
            log.error("2. Environment variable:");
            log.error("   export DEEPGRAM_API_KEY=your_api_key_here");
            log.error("");
            log.error("Get your API key at: https://console.deepgram.com");
            log.error("");
            System.exit(1);
        }

        int port = 8081;
        String portEnv = dotenv.get("PORT");
        if (portEnv != null && !portEnv.isBlank()) {
            try { port = Integer.parseInt(portEnv); } catch (NumberFormatException ignored) {}
        }

        String host = dotenv.get("HOST");
        if (host == null || host.isBlank()) {
            host = "0.0.0.0";
        }

        // Session secret for JWT signing
        String sessionSecretEnv = dotenv.get("SESSION_SECRET");
        String sessionSecret;
        if (sessionSecretEnv != null && !sessionSecretEnv.isBlank()) {
            sessionSecret = sessionSecretEnv;
        } else {
            byte[] randomBytes = new byte[32];
            new SecureRandom().nextBytes(randomBytes);
            sessionSecret = bytesToHex(randomBytes);
        }

        jwtAlgorithm = Algorithm.HMAC256(sessionSecret);
        jwtVerifier = JWT.require(jwtAlgorithm).build();

        // ====================================================================
        // DEEPGRAM SDK CLIENT SETUP
        // ====================================================================

        deepgram = DeepgramClient.builder().apiKey(deepgramApiKey).build();

        // ====================================================================
        // JAVALIN SERVER SETUP
        // ====================================================================

        final String finalHost = host;

        Javalin app = Javalin.create(config -> {
            config.jetty.defaultHost = finalHost;
            config.bundledPlugins.enableCors(cors -> {
                cors.addRule(rule -> {
                    rule.anyHost();
                });
            });
        });

        // ====================================================================
        // HTTP ROUTES
        // ====================================================================

        // GET /api/session - Issue JWT session token
        app.get("/api/session", ctx -> {
            String token = issueToken();
            ctx.json(Map.of("token", token));
        });

        // GET /api/metadata - Return [meta] section from deepgram.toml
        app.get("/api/metadata", ctx -> {
            try {
                Map<String, Object> meta = loadMetadata();
                ctx.json(meta);
            } catch (Exception e) {
                log.error("Error reading metadata: {}", e.getMessage());
                ctx.status(500).json(Map.of(
                    "error", "INTERNAL_SERVER_ERROR",
                    "message", "Failed to read metadata from deepgram.toml: " + e.getMessage()
                ));
            }
        });

        // GET /health - Health check
        app.get("/health", ctx -> {
            ctx.json(Map.of("status", "ok"));
        });

        // ====================================================================
        // WEBSOCKET ENDPOINT
        // ====================================================================

        app.ws("/api/live-transcription", (WsConfig ws) -> {

            ws.onConnect(clientCtx -> {
                // Validate JWT from Sec-WebSocket-Protocol: access_token.<jwt>
                String validProtocol = validateWsToken(clientCtx);

                if (validProtocol == null) {
                    log.warn("WebSocket auth failed: invalid or missing token");
                    clientCtx.closeSession(4401, "Unauthorized");
                    return;
                }

                String connectionId = UUID.randomUUID().toString().substring(0, 8);
                clientCtx.attribute("connectionId", connectionId);
                activeConnections.put(connectionId, clientCtx);

                log.info("[{}] Client connected to /api/live-transcription (authenticated)", connectionId);

                // Parse query parameters with defaults
                String model = paramOrDefault(clientCtx.queryParam("model"), "nova-3");
                String language = paramOrDefault(clientCtx.queryParam("language"), "en");
                String smartFormat = paramOrDefault(clientCtx.queryParam("smart_format"), "true");
                String encoding = paramOrDefault(clientCtx.queryParam("encoding"), "linear16");
                String sampleRate = paramOrDefault(clientCtx.queryParam("sample_rate"), "16000");
                String channels = paramOrDefault(clientCtx.queryParam("channels"), "1");

                log.info("[{}] Connecting to Deepgram STT: model={}, language={}, encoding={}, sample_rate={}, channels={}",
                    connectionId, model, language, encoding, sampleRate, channels);

                // Create a per-connection Deepgram SDK WebSocket client.
                V1WebSocketClient dg = deepgram.listen().v1().v1WebSocket();
                SttBridge bridge = new SttBridge(dg, connectionId);
                clientCtx.attribute("bridge", bridge);

                // Deepgram -> browser. The SDK's typed objects serialize to the same
                // Deepgram wire JSON the frontend already parses (type/channel/is_final/...).
                dg.onConnected(() -> log.info("[{}] Connected to Deepgram STT API", connectionId));
                dg.onResults(results -> forwardJson(clientCtx, connectionId, results));
                dg.onMetadata(metadata -> forwardJson(clientCtx, connectionId, metadata));
                dg.onUtteranceEnd(utteranceEnd -> forwardJson(clientCtx, connectionId, utteranceEnd));
                dg.onSpeechStarted(speechStarted -> forwardJson(clientCtx, connectionId, speechStarted));

                dg.onError(error -> {
                    log.error("[{}] Deepgram WebSocket error: {}", connectionId, error.getMessage());
                    try {
                        if (clientCtx.session.isOpen()) {
                            clientCtx.closeSession(1011, "Deepgram connection error");
                        }
                    } catch (Exception e) {
                        log.error("[{}] Error closing client after Deepgram error: {}", connectionId, e.getMessage());
                    }
                });

                dg.onDisconnected(reason -> {
                    log.info("[{}] Deepgram connection closed: {} {}", connectionId, reason.getCode(), reason.getReason());
                    try {
                        if (clientCtx.session.isOpen()) {
                            int safeCode = getSafeCloseCode(reason.getCode());
                            clientCtx.closeSession(safeCode,
                                reason.getReason() != null ? reason.getReason() : "Deepgram connection closed");
                        }
                    } catch (Exception e) {
                        log.error("[{}] Error closing client after Deepgram close: {}", connectionId, e.getMessage());
                    }
                });

                // Build connection options from the frontend's query parameters.
                V1ConnectOptions options = V1ConnectOptions.builder()
                    .model(ListenV1Model.valueOf(model))
                    .language(ListenV1Language.of(language))
                    .encoding(ListenV1Encoding.valueOf(encoding))
                    .sampleRate(ListenV1SampleRate.of(Integer.parseInt(sampleRate)))
                    .channels(ListenV1Channels.of(Integer.parseInt(channels)))
                    .smartFormat(ListenV1SmartFormat.valueOf(smartFormat))
                    .build();

                dg.connect(options).whenComplete((v, err) -> {
                    if (err != null) {
                        log.error("[{}] Failed to connect to Deepgram: {}", connectionId, err.getMessage());
                        try {
                            if (clientCtx.session.isOpen()) {
                                clientCtx.closeSession(1011, "Failed to connect to Deepgram");
                            }
                        } catch (Exception ignored) {}
                        activeConnections.remove(connectionId);
                        return;
                    }
                    // Flush any audio the browser sent before the Deepgram socket opened.
                    bridge.markReady();
                });
            });

            ws.onMessage(clientCtx -> {
                // The frontend streams only binary audio; text control frames are
                // not used by this app. Log and ignore anything unexpected.
                String connectionId = clientCtx.attribute("connectionId");
                log.debug("[{}] Ignoring unexpected text message from client", connectionId);
            });

            ws.onBinaryMessage(clientCtx -> {
                // Forward binary audio from the client to Deepgram.
                SttBridge bridge = clientCtx.attribute("bridge");
                if (bridge != null) {
                    bridge.sendAudio(ByteString.of(clientCtx.data()));
                }
            });

            ws.onClose(clientCtx -> {
                String connectionId = clientCtx.attribute("connectionId");
                if (connectionId == null) return;

                log.info("[{}] Client disconnected: {} {}", connectionId,
                    clientCtx.status(), clientCtx.reason());

                // Close the Deepgram connection when the client disconnects.
                SttBridge bridge = clientCtx.attribute("bridge");
                if (bridge != null) {
                    bridge.closeStream();
                    bridge.disconnect();
                }

                activeConnections.remove(connectionId);
                log.info("[{}] Connection closed ({} active)", connectionId, activeConnections.size());
            });

            ws.onError(clientCtx -> {
                String connectionId = clientCtx.attribute("connectionId");
                if (connectionId == null) return;

                log.error("[{}] Client WebSocket error: {}", connectionId,
                    clientCtx.error() != null ? clientCtx.error().getMessage() : "unknown");

                // Close the Deepgram connection on client error.
                SttBridge bridge = clientCtx.attribute("bridge");
                if (bridge != null) {
                    bridge.disconnect();
                }

                activeConnections.remove(connectionId);
            });
        });

        // ====================================================================
        // GRACEFUL SHUTDOWN
        // ====================================================================

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            log.info("");
            log.info("Shutting down... Closing {} active connection(s)...", activeConnections.size());

            for (Map.Entry<String, WsContext> entry : activeConnections.entrySet()) {
                try {
                    WsContext ctx = entry.getValue();
                    if (ctx.session.isOpen()) {
                        ctx.closeSession(1001, "Server shutting down");
                    }
                } catch (Exception e) {
                    log.error("Error closing connection {}: {}", entry.getKey(), e.getMessage());
                }
            }

            log.info("All connections closed.");
        }));

        // ====================================================================
        // SERVER START
        // ====================================================================

        app.start(port);

        String secretPreview = sessionSecret.length() >= 16
            ? sessionSecret.substring(0, 16) + "..."
            : sessionSecret + "...";

        log.info("");
        log.info("======================================================================");
        log.info("Backend API Server running at http://localhost:{}", port);
        log.info("");
        log.info("  GET  /api/session");
        log.info("  WS   /api/live-transcription (auth required)");
        log.info("  GET  /api/metadata");
        log.info("  GET  /health");
        log.info("");
        log.info("Session secret: {} (first 16 chars)", secretPreview);
        log.info("======================================================================");
        log.info("");
    }

    // ========================================================================
    // SESSION AUTH - JWT tokens for production security
    // ========================================================================

    /**
     * Issues a signed JWT with a 1-hour expiry.
     *
     * @return signed JWT string
     */
    private static String issueToken() {
        Instant now = Instant.now();
        return JWT.create()
            .withIssuedAt(now)
            .withExpiresAt(now.plusSeconds(JWT_EXPIRY_SECONDS))
            .sign(jwtAlgorithm);
    }

    /**
     * Validates a JWT token string.
     *
     * @param token the JWT string to validate
     * @return true if valid, false otherwise
     */
    private static boolean validateToken(String token) {
        try {
            jwtVerifier.verify(token);
            return true;
        } catch (JWTVerificationException e) {
            return false;
        }
    }

    /**
     * Validates a JWT from the WebSocket Sec-WebSocket-Protocol header.
     * Looks for a subprotocol matching "access_token.<jwt>" and verifies the JWT.
     *
     * @param ctx the WebSocket context
     * @return the full valid subprotocol string, or null if invalid
     */
    private static String validateWsToken(WsContext ctx) {
        String protocolHeader = ctx.header("Sec-WebSocket-Protocol");
        if (protocolHeader == null || protocolHeader.isBlank()) {
            return null;
        }

        String[] protocols = protocolHeader.split(",");
        for (String proto : protocols) {
            String trimmed = proto.trim();
            if (trimmed.startsWith("access_token.")) {
                String token = trimmed.substring("access_token.".length());
                if (validateToken(token)) {
                    return trimmed;
                }
            }
        }
        return null;
    }

    // ========================================================================
    // METADATA - deepgram.toml parsing
    // ========================================================================

    /**
     * Reads and parses the [meta] section from deepgram.toml.
     *
     * @return map of metadata key-value pairs
     * @throws Exception if file cannot be read or [meta] section is missing
     */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> loadMetadata() throws Exception {
        File tomlFile = new File("deepgram.toml");
        if (!tomlFile.exists()) {
            throw new RuntimeException("deepgram.toml not found");
        }

        TomlMapper tomlMapper = new TomlMapper();
        Map<String, Object> config = tomlMapper.readValue(tomlFile, Map.class);

        Object metaObj = config.get("meta");
        if (metaObj == null) {
            throw new RuntimeException("Missing [meta] section in deepgram.toml");
        }

        if (metaObj instanceof Map) {
            return (Map<String, Object>) metaObj;
        }

        throw new RuntimeException("Invalid [meta] section in deepgram.toml");
    }

    // ========================================================================
    // HELPER FUNCTIONS
    // ========================================================================

    /**
     * Serializes a Deepgram SDK event object to JSON and forwards it to the
     * browser client as a text frame. The SDK types serialize to the same wire
     * format Deepgram sends, so the frontend needs no changes.
     */
    private static void forwardJson(WsContext clientCtx, String connectionId, Object message) {
        try {
            if (clientCtx.session.isOpen()) {
                clientCtx.send(jsonMapper.writeValueAsString(message));
            }
        } catch (Exception e) {
            log.error("[{}] Error forwarding message to client: {}", connectionId, e.getMessage());
        }
    }

    /**
     * Returns the value if non-null and non-blank, otherwise returns the default.
     */
    private static String paramOrDefault(String value, String defaultValue) {
        return (value != null && !value.isBlank()) ? value : defaultValue;
    }

    /**
     * Returns a safe WebSocket close code, avoiding reserved codes.
     * Falls back to 1000 (normal closure) for reserved or invalid codes.
     *
     * @param code the close code to check
     * @return a safe close code
     */
    static int getSafeCloseCode(int code) {
        if (code >= 1000 && code <= 4999 && !RESERVED_CLOSE_CODES.contains(code)) {
            return code;
        }
        return 1000;
    }

    /**
     * Converts a byte array to a lowercase hex string.
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // ========================================================================
    // DEEPGRAM WEBSOCKET BRIDGE (SDK client-side)
    // ========================================================================

    /**
     * Per-connection bridge to a Deepgram Live STT WebSocket. Buffers audio that
     * arrives from the browser before the Deepgram socket has finished opening.
     */
    static final class SttBridge {

        private final V1WebSocketClient dg;
        private final String connectionId;
        private boolean ready = false;
        private final List<ByteString> pending = new ArrayList<>();

        SttBridge(V1WebSocketClient dg, String connectionId) {
            this.dg = dg;
            this.connectionId = connectionId;
        }

        /** Forwards an audio chunk to Deepgram, buffering until the socket is open. */
        synchronized void sendAudio(ByteString audio) {
            if (!ready) {
                pending.add(audio);
                return;
            }
            try {
                dg.sendMedia(audio);
            } catch (Exception e) {
                log.error("[{}] Error sending audio to Deepgram: {}", connectionId, e.getMessage());
            }
        }

        /** Marks the Deepgram socket ready and flushes any buffered audio. */
        synchronized void markReady() {
            ready = true;
            for (ByteString audio : pending) {
                try {
                    dg.sendMedia(audio);
                } catch (Exception e) {
                    log.error("[{}] Error flushing buffered audio to Deepgram: {}", connectionId, e.getMessage());
                }
            }
            pending.clear();
        }

        /** Signals end-of-stream to Deepgram so it can flush final results. */
        void closeStream() {
            try {
                dg.sendCloseStream(ListenV1CloseStream.builder()
                    .type(ListenV1CloseStreamType.CLOSE_STREAM)
                    .build());
            } catch (Exception ignored) {
                // socket may already be closed
            }
        }

        /** Tears down the Deepgram WebSocket connection. */
        void disconnect() {
            try {
                dg.disconnect();
            } catch (Exception ignored) {
                // already closed
            }
        }
    }
}
