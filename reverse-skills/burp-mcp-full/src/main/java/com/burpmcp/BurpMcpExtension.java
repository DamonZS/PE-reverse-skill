package com.burpmcp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

/**
 * BurpSuite MCP Full Control Extension
 * Exposes ALL Burp functionality via MCP protocol on HTTP port 9876
 * 
 * Features:
 * - Proxy history access & filtering
 * - Intruder attack control (create, configure payloads, start, get results)
 * - Repeater tab management
 * - Scanner control
 * - Sitemap access
 * - Send HTTP requests through Burp
 * - Intercept control
 * - Encoding/decoding utilities
 */
public class BurpMcpExtension implements BurpExtension {

    private MontoyaApi api;
    private Logging logging;
    private McpHttpServer server;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();

        api.extension().setName("MCP Full Control");

        int port = resolvePort(logging);
        try {
            server = new McpHttpServer(api, port);
            server.start();
            logging.logToOutput("[MCP] Server started on http://127.0.0.1:" + port);
            logging.logToOutput("[MCP] Configure port via -Dburp.mcp.port=<n> or BURP_MCP_PORT env var (default 9876)");
            logging.logToOutput("[MCP] Auth token: ~/.burp-mcp-token (override with -Dburp.mcp.token or BURP_MCP_TOKEN)");
            logging.logToOutput("[MCP] Tools: proxy_history, send_request, intruder_attack, repeater, scanner, sitemap, intercept, encode/decode");
        } catch (Exception e) {
            logging.logToError("[MCP] Failed to start server on port " + port + ": " + e.getMessage());
            logging.logToError("[MCP] If port is in use, set -Dburp.mcp.port=<other> and restart Burp.");
        }

        api.extension().registerUnloadingHandler(() -> {
            if (server != null) {
                server.stop();
                logging.logToOutput("[MCP] Server stopped");
            }
        });
    }

    private int resolvePort(Logging logging) {
        String prop = System.getProperty("burp.mcp.port");
        String env = System.getenv("BURP_MCP_PORT");
        String raw = prop != null ? prop : env;
        if (raw == null || raw.isBlank()) return 9876;
        try {
            int p = Integer.parseInt(raw.trim());
            if (p < 1 || p > 65535) throw new IllegalArgumentException("out of range");
            if (prop != null) logging.logToOutput("[MCP] Port from -Dburp.mcp.port: " + p);
            else logging.logToOutput("[MCP] Port from BURP_MCP_PORT: " + p);
            return p;
        } catch (Exception e) {
            logging.logToError("[MCP] Invalid port '" + raw + "', falling back to 9876. " + e.getMessage());
            return 9876;
        }
    }
}
