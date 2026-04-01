/**
 * Java Live Transcription Starter - Backend Server
 *
 * A WebSocket proxy server that forwards audio and transcription messages
 * between browser clients and Deepgram's Live Speech-to-Text API using
 * the Deepgram Java SDK.
 *
 * Key Features:
 * - WebSocket proxy: /api/live-transcription -> Deepgram V1 Listen WebSocket
 * - Bidirectional message forwarding (binary audio + JSON results)
 * - JWT session auth via Sec-WebSocket-Protocol subprotocol
 * - Metadata endpoint: GET /api/metadata
 * - CORS enabled for frontend communication
 * - Uses Deepgram Java SDK for WebSocket connection management
 *
 * Routes:
 *   GET  /api/session              - Issue JWT session token
 *   GET  /api/metadata             - Project metadata from deepgram.toml
 *   WS   /api/live-transcription   - WebSocket proxy to Deepgram STT (auth required)
 *   GET  /health                   - Health check
 */

package com.deepgram.starter;

// ============================================================================
// SECTION 1: IMPORTS
// ============================================================================

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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.deepgram.DeepgramClient;
import com.deepgram.resources.listen.v1.websocket.V1WebSocketClient;
import com.deepgram.resources.listen.v1.websocket.V1ConnectOptions;
import com.deepgram.types.ListenV1Model;
import com.deepgram.types.ListenV1Language;
import com.deepgram.types.ListenV1SmartFormat;
import com.deepgram.types.ListenV1Encoding;
import com.deepgram.types.ListenV1SampleRate;
import com.deepgram.types.ListenV1Channels;

import okio.ByteString;

import java.io.File;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

// ============================================================================
// SECTION 2: MAIN APPLICATION
// ============================================================================

public class App {

    private static final Logger log = LoggerFactory.getLogger(App.class);

    // ========================================================================
    // SECTION 3: CONFIGURATION
    // ========================================================================

    private static final int JWT_EXPIRY_SECONDS = 3600; // 1 hour

    /** Deepgram API key loaded from environment. */
    private static String deepgramApiKey;

    /** JWT signing algorithm. */
    private static Algorithm jwtAlgorithm;

    /** JWT verifier. */
    private static JWTVerifier jwtVerifier;

    /** Jackson ObjectMapper for JSON serialization. */
    private static final ObjectMapper jsonMapper = new ObjectMapper();

    /** Map of browser WsContext -> SDK V1WebSocketClient for cleanup. */
    private static final ConcurrentHashMap<WsContext, V1WebSocketClient> activeConnections =
            new ConcurrentHashMap<>();

    // ========================================================================
    // SECTION 4: ENTRY POINT
    // ========================================================================

    /**
     * Application entry point. Loads configuration, validates the API key,
     * and starts the Javalin HTTP server with WebSocket support.
     *
     * @param args Command-line arguments (unused)
     */
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

        app.ws("/api/live-transcription", App::handleLiveTranscription);

        // ====================================================================
        // SERVER START
        // ====================================================================

        app.start(port);

        log.info("");
        log.info("======================================================================");
        log.info("  Backend API running at http://localhost:{}", port);
        log.info("  GET  /api/session");
        log.info("  WS   /api/live-transcription (auth required)");
        log.info("  GET  /api/metadata");
        log.info("  GET  /health");
        log.info("======================================================================");
        log.info("");
    }

    // ========================================================================
    // SECTION 5: WEBSOCKET ROUTE - Live Transcription Proxy
    // ========================================================================

    /**
     * Configures the WebSocket endpoint for live transcription.
     * Acts as a bidirectional proxy: browser <-> Javalin <-> Deepgram SDK V1 WebSocket.
     *
     * The SDK handles the outbound connection to Deepgram, authentication,
     * and WebSocket lifecycle. This handler bridges the browser's WebSocket
     * connection to the SDK's WebSocket client.
     *
     * @param ws Javalin WebSocket config
     */
    private static void handleLiveTranscription(WsConfig ws) {

        ws.onConnect(clientCtx -> {
            // Validate JWT from Sec-WebSocket-Protocol: access_token.<jwt>
            String validProtocol = validateWsToken(clientCtx);

            if (validProtocol == null) {
                log.warn("WebSocket auth failed: invalid or missing token");
                clientCtx.closeSession(4401, "Unauthorized");
                return;
            }

            log.info("Client connected to /api/live-transcription (authenticated)");

            // Parse query parameters with defaults
            String model = paramOrDefault(clientCtx.queryParam("model"), "nova-3");
            String language = paramOrDefault(clientCtx.queryParam("language"), "en");
            String smartFormat = paramOrDefault(clientCtx.queryParam("smart_format"), "true");
            String encoding = paramOrDefault(clientCtx.queryParam("encoding"), "linear16");
            String sampleRate = paramOrDefault(clientCtx.queryParam("sample_rate"), "16000");
            String channels = paramOrDefault(clientCtx.queryParam("channels"), "1");

            log.info("Connecting to Deepgram STT: model={}, language={}, encoding={}, sample_rate={}, channels={}",
                model, language, encoding, sampleRate, channels);

            // Create SDK client for this connection
            DeepgramClient dgClient = DeepgramClient.builder()
                    .apiKey(deepgramApiKey)
                    .build();

            V1WebSocketClient dgWs = dgClient.listen().v1().v1WebSocket();

            // Forward all text messages (transcripts/events) from Deepgram to browser
            dgWs.onMessage(json -> {
                try {
                    if (clientCtx.session.isOpen()) {
                        clientCtx.send(json);
                    }
                } catch (Exception e) {
                    log.error("Error forwarding transcript to browser: {}", e.getMessage());
                }
            });

            dgWs.onError(e -> {
                log.error("Deepgram WebSocket error: {}", e.getMessage());
                try {
                    if (clientCtx.session.isOpen()) {
                        clientCtx.closeSession(1011, "Deepgram connection error");
                    }
                } catch (Exception ignored) {}
            });

            dgWs.onDisconnected(reason -> {
                log.info("Deepgram connection closed: {}", reason);
                try {
                    if (clientCtx.session.isOpen()) {
                        clientCtx.closeSession(1000, "Deepgram disconnected");
                    }
                } catch (Exception ignored) {}
                activeConnections.remove(clientCtx);
            });

            // Build connection options using SDK builder
            V1ConnectOptions.Builder optionsBuilder = (V1ConnectOptions.Builder)
                    V1ConnectOptions.builder()
                            .model(ListenV1Model.valueOf(model));
            optionsBuilder
                    .language(ListenV1Language.of(language))
                    .smartFormat(ListenV1SmartFormat.valueOf(smartFormat))
                    .encoding(ListenV1Encoding.valueOf(encoding))
                    .sampleRate(ListenV1SampleRate.of(Integer.parseInt(sampleRate)))
                    .channels(ListenV1Channels.of(Integer.parseInt(channels)));
            V1ConnectOptions options = optionsBuilder.build();

            // Connect to Deepgram via SDK
            dgWs.connect(options).thenRun(() -> {
                activeConnections.put(clientCtx, dgWs);
                log.info("Live transcription session started (model={})", model);
            }).exceptionally(e -> {
                log.error("Failed to connect to Deepgram: {}", e.getMessage());
                try {
                    clientCtx.closeSession(1011, "Failed to connect to Deepgram");
                } catch (Exception ignored) {}
                return null;
            });
        });

        // Forward text messages from client to Deepgram
        ws.onMessage(clientCtx -> {
            V1WebSocketClient dgWs = activeConnections.get(clientCtx);
            if (dgWs != null) {
                String text = clientCtx.message();
                dgWs.sendMedia(ByteString.encodeUtf8(text));
            }
        });

        // Forward binary messages (audio) from client to Deepgram via SDK
        ws.onBinaryMessage(clientCtx -> {
            V1WebSocketClient dgWs = activeConnections.get(clientCtx);
            if (dgWs != null) {
                byte[] data = clientCtx.data();
                int offset = clientCtx.offset();
                int length = clientCtx.length();
                byte[] audioData = new byte[length];
                System.arraycopy(data, offset, audioData, 0, length);
                dgWs.sendMedia(ByteString.of(audioData));
            }
        });

        // Handle client disconnect - clean up Deepgram connection
        ws.onClose(clientCtx -> {
            log.info("Client disconnected: {} {}", clientCtx.status(), clientCtx.reason());

            V1WebSocketClient dgWs = activeConnections.remove(clientCtx);
            if (dgWs != null) {
                try {
                    dgWs.disconnect();
                } catch (Exception ignored) {}
            }
            log.info("Live transcription session ended ({} active)", activeConnections.size());
        });

        // Handle client errors
        ws.onError(clientCtx -> {
            log.error("Client WebSocket error: {}",
                clientCtx.error() != null ? clientCtx.error().getMessage() : "unknown");

            V1WebSocketClient dgWs = activeConnections.remove(clientCtx);
            if (dgWs != null) {
                try {
                    dgWs.disconnect();
                } catch (Exception ignored) {}
            }
        });
    }

    // ========================================================================
    // SECTION 6: SESSION AUTH — JWT tokens for production security
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
    // SECTION 7: METADATA - deepgram.toml parsing
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
    // SECTION 8: HELPER FUNCTIONS
    // ========================================================================

    /**
     * Returns the value if non-null and non-blank, otherwise returns the default.
     */
    private static String paramOrDefault(String value, String defaultValue) {
        return (value != null && !value.isBlank()) ? value : defaultValue;
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
}
