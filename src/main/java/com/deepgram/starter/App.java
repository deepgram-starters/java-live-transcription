/**
 * Java Live Transcription Starter - Backend Server
 *
 * A WebSocket proxy server that transparently forwards audio and transcription
 * messages between browser clients and Deepgram's Live Speech-to-Text API.
 *
 * Key Features:
 * - WebSocket proxy: /api/live-transcription -> wss://api.deepgram.com/v1/listen
 * - Bidirectional message forwarding (binary audio + JSON results)
 * - JWT session auth via Sec-WebSocket-Protocol subprotocol
 * - Metadata endpoint: GET /api/metadata
 * - CORS enabled for frontend communication
 * - Graceful shutdown with connection tracking
 *
 * Routes:
 *   GET  /api/session              - Issue JWT session token
 *   GET  /api/metadata             - Project metadata from deepgram.toml
 *   WS   /api/live-transcription   - WebSocket proxy to Deepgram STT (auth required)
 *   GET  /health                   - Health check
 */

package com.deepgram.starter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.toml.TomlMapper;
import io.github.cdimascio.dotenv.Dotenv;
import io.javalin.Javalin;
import io.javalin.websocket.WsConfig;
import io.javalin.websocket.WsContext;
import org.eclipse.jetty.websocket.api.Callback;
import org.eclipse.jetty.websocket.api.Session;
import org.eclipse.jetty.websocket.api.StatusCode;
import org.eclipse.jetty.websocket.client.ClientUpgradeRequest;
import org.eclipse.jetty.websocket.client.WebSocketClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

// ============================================================================
// MAIN APPLICATION
// ============================================================================

public class App {

    private static final Logger log = LoggerFactory.getLogger(App.class);

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    private static final String DEEPGRAM_STT_URL = "wss://api.deepgram.com/v1/listen";
    private static final int JWT_EXPIRY_SECONDS = 3600; // 1 hour

    /** Reserved WebSocket close codes that must not be sent by applications. */
    private static final Set<Integer> RESERVED_CLOSE_CODES = Set.of(1004, 1005, 1006, 1015);

    /** Track active client WebSocket sessions for graceful shutdown. */
    private static final Map<String, WsContext> activeConnections = new ConcurrentHashMap<>();

    /** Shared Jetty WebSocket client for outbound connections to Deepgram. */
    private static WebSocketClient jettyWsClient;

    /** Deepgram API key loaded from environment. */
    private static String deepgramApiKey;

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
        deepgramApiKey = dotenv.get("DEEPGRAM_API_KEY");
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
        // JETTY WEBSOCKET CLIENT SETUP
        // ====================================================================

        jettyWsClient = new WebSocketClient();
        jettyWsClient.start();

        // ====================================================================
        // JAVALIN SERVER SETUP
        // ====================================================================

        final int finalPort = port;
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

                // Build Deepgram URL with query parameters
                String deepgramUrl = buildDeepgramUrl(model, language, smartFormat, encoding, sampleRate, channels);

                log.info("[{}] Connecting to Deepgram STT: model={}, language={}, encoding={}, sample_rate={}, channels={}",
                    connectionId, model, language, encoding, sampleRate, channels);

                // Connect to Deepgram using Jetty WebSocket client
                try {
                    URI dgUri = new URI(deepgramUrl);
                    ClientUpgradeRequest upgradeRequest = new ClientUpgradeRequest();
                    upgradeRequest.setHeader("Authorization", "Token " + deepgramApiKey);

                    // Latch to wait for Deepgram connection to open
                    CountDownLatch openLatch = new CountDownLatch(1);

                    DeepgramEndpoint dgEndpoint = new DeepgramEndpoint(clientCtx, connectionId, openLatch);
                    jettyWsClient.connect(dgEndpoint, dgUri, upgradeRequest);

                    // Wait for the Deepgram connection to be established (up to 10 seconds)
                    if (!openLatch.await(10, TimeUnit.SECONDS)) {
                        log.error("[{}] Timeout connecting to Deepgram", connectionId);
                        clientCtx.closeSession(1011, "Timeout connecting to Deepgram");
                        activeConnections.remove(connectionId);
                        return;
                    }

                    // Store the Deepgram session on the client context for message forwarding
                    clientCtx.attribute("deepgramEndpoint", dgEndpoint);

                    log.info("[{}] Connected to Deepgram STT API", connectionId);

                } catch (Exception e) {
                    log.error("[{}] Failed to connect to Deepgram: {}", connectionId, e.getMessage());
                    clientCtx.closeSession(1011, "Failed to connect to Deepgram");
                    activeConnections.remove(connectionId);
                }
            });

            ws.onMessage(clientCtx -> {
                // Forward text messages from client to Deepgram
                String connectionId = clientCtx.attribute("connectionId");
                DeepgramEndpoint dgEndpoint = clientCtx.attribute("deepgramEndpoint");

                if (dgEndpoint != null && dgEndpoint.isOpen()) {
                    String text = clientCtx.message();
                    dgEndpoint.sendText(text);
                }
            });

            ws.onBinaryMessage(clientCtx -> {
                // Forward binary messages (audio) from client to Deepgram
                String connectionId = clientCtx.attribute("connectionId");
                DeepgramEndpoint dgEndpoint = clientCtx.attribute("deepgramEndpoint");

                if (dgEndpoint != null && dgEndpoint.isOpen()) {
                    byte[] data = clientCtx.data();
                    dgEndpoint.sendBinary(data);
                }
            });

            ws.onClose(clientCtx -> {
                String connectionId = clientCtx.attribute("connectionId");
                if (connectionId == null) return;

                log.info("[{}] Client disconnected: {} {}", connectionId,
                    clientCtx.status(), clientCtx.reason());

                // Close Deepgram connection when client disconnects
                DeepgramEndpoint dgEndpoint = clientCtx.attribute("deepgramEndpoint");
                if (dgEndpoint != null && dgEndpoint.isOpen()) {
                    dgEndpoint.close(StatusCode.NORMAL, "Client disconnected");
                }

                activeConnections.remove(connectionId);
                log.info("[{}] Connection closed ({} active)", connectionId, activeConnections.size());
            });

            ws.onError(clientCtx -> {
                String connectionId = clientCtx.attribute("connectionId");
                if (connectionId == null) return;

                log.error("[{}] Client WebSocket error: {}", connectionId,
                    clientCtx.error() != null ? clientCtx.error().getMessage() : "unknown");

                // Close Deepgram connection on client error
                DeepgramEndpoint dgEndpoint = clientCtx.attribute("deepgramEndpoint");
                if (dgEndpoint != null && dgEndpoint.isOpen()) {
                    dgEndpoint.close(StatusCode.SERVER_ERROR, "Client error");
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

            try {
                if (jettyWsClient != null) {
                    jettyWsClient.stop();
                }
            } catch (Exception e) {
                log.error("Error stopping WebSocket client: {}", e.getMessage());
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
     * Builds the Deepgram WebSocket URL with query parameters.
     *
     * @return full Deepgram URL string with query parameters
     */
    private static String buildDeepgramUrl(String model, String language, String smartFormat,
                                            String encoding, String sampleRate, String channels) {
        StringBuilder sb = new StringBuilder(DEEPGRAM_STT_URL);
        sb.append("?model=").append(urlEncode(model));
        sb.append("&language=").append(urlEncode(language));
        sb.append("&smart_format=").append(urlEncode(smartFormat));
        sb.append("&encoding=").append(urlEncode(encoding));
        sb.append("&sample_rate=").append(urlEncode(sampleRate));
        sb.append("&channels=").append(urlEncode(channels));
        return sb.toString();
    }

    /**
     * Returns the value if non-null and non-blank, otherwise returns the default.
     */
    private static String paramOrDefault(String value, String defaultValue) {
        return (value != null && !value.isBlank()) ? value : defaultValue;
    }

    /**
     * URL-encodes a string value.
     */
    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
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
        return StatusCode.NORMAL;
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
    // DEEPGRAM WEBSOCKET ENDPOINT (Jetty client-side)
    // ========================================================================

    /**
     * Jetty WebSocket endpoint that connects to Deepgram and forwards messages
     * bidirectionally with the client WebSocket.
     */
    static class DeepgramEndpoint extends org.eclipse.jetty.websocket.api.Session.Listener.Abstract {

        private final WsContext clientCtx;
        private final String connectionId;
        private final CountDownLatch openLatch;
        private Session dgSession;
        private long dgToClientCount = 0;
        private long clientToDgCount = 0;

        DeepgramEndpoint(WsContext clientCtx, String connectionId, CountDownLatch openLatch) {
            this.clientCtx = clientCtx;
            this.connectionId = connectionId;
            this.openLatch = openLatch;
        }

        @Override
        public void onWebSocketOpen(Session session) {
            super.onWebSocketOpen(session);
            this.dgSession = session;
            openLatch.countDown();
        }

        @Override
        public void onWebSocketText(String message) {
            // Forward text messages from Deepgram to client
            dgToClientCount++;
            if (dgToClientCount % 10 == 0 || dgToClientCount <= 3) {
                log.debug("[{}] deepgram->client #{} (text, size: {})",
                    connectionId, dgToClientCount, message.length());
            }

            try {
                if (clientCtx.session.isOpen()) {
                    clientCtx.send(message);
                }
            } catch (Exception e) {
                log.error("[{}] Error forwarding text to client: {}", connectionId, e.getMessage());
            }
        }

        @Override
        public void onWebSocketBinary(ByteBuffer payload, Callback callback) {
            // Forward binary messages from Deepgram to client
            dgToClientCount++;
            if (dgToClientCount % 100 == 0) {
                log.debug("[{}] deepgram->client #{} (binary, size: {})",
                    connectionId, dgToClientCount, payload.remaining());
            }

            try {
                if (clientCtx.session.isOpen()) {
                    byte[] data = new byte[payload.remaining()];
                    payload.get(data);
                    clientCtx.send(ByteBuffer.wrap(data));
                }
                callback.succeed();
            } catch (Exception e) {
                log.error("[{}] Error forwarding binary to client: {}", connectionId, e.getMessage());
                callback.fail(e);
            }
        }

        @Override
        public void onWebSocketClose(int statusCode, String reason) {
            log.info("[{}] Deepgram connection closed: {} {}", connectionId, statusCode, reason);

            // Close client connection when Deepgram disconnects
            try {
                if (clientCtx.session.isOpen()) {
                    int safeCode = getSafeCloseCode(statusCode);
                    clientCtx.closeSession(safeCode, reason != null ? reason : "Deepgram connection closed");
                }
            } catch (Exception e) {
                log.error("[{}] Error closing client after Deepgram close: {}", connectionId, e.getMessage());
            }
        }

        @Override
        public void onWebSocketError(Throwable cause) {
            log.error("[{}] Deepgram WebSocket error: {}", connectionId, cause.getMessage());

            try {
                if (clientCtx.session.isOpen()) {
                    clientCtx.closeSession(1011, "Deepgram connection error");
                }
            } catch (Exception e) {
                log.error("[{}] Error closing client after Deepgram error: {}", connectionId, e.getMessage());
            }
        }

        /** Checks if the Deepgram WebSocket session is open. */
        boolean isOpen() {
            return dgSession != null && dgSession.isOpen();
        }

        /** Sends a text message to Deepgram. */
        void sendText(String text) {
            if (isOpen()) {
                clientToDgCount++;
                dgSession.sendText(text, Callback.NOOP);
            }
        }

        /** Sends binary data to Deepgram. */
        void sendBinary(byte[] data) {
            if (isOpen()) {
                clientToDgCount++;
                dgSession.sendBinary(ByteBuffer.wrap(data), Callback.NOOP);
            }
        }

        /** Closes the Deepgram WebSocket connection. */
        void close(int code, String reason) {
            if (isOpen()) {
                dgSession.close(code, reason, Callback.NOOP);
            }
        }
    }
}
