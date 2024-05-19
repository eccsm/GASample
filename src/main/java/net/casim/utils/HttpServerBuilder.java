package net.casim.utils;

import com.bettercloud.vault.VaultException;
import com.google.gson.Gson;
import com.google.zxing.WriterException;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

public class HttpServerBuilder {
    private static final Logger logger = LoggerFactory.getLogger(HttpServerBuilder.class);

    public static void startServer() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/", new RootHandler());
        server.createContext("/authenticate", new AuthenticateHandler());
        server.createContext("/verifyOTP", new VerifyOTPHandler());
        server.createContext("/barcode", new BarcodeHandler());
        server.setExecutor(null);
        server.start();
        logger.info("Server started on port 8080");
    }

    static class RootHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String response = "";
            try {
                File file = new File("src/main/resources/static/index.html");
                response = new String(Files.readAllBytes(Paths.get(file.getAbsolutePath())));
                exchange.sendResponseHeaders(200, response.length());
            } catch (IOException e) {
                exchange.sendResponseHeaders(500, 0);
                logger.error("Error handling root request", e);
            }
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }

    static class AuthenticateHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("POST".equals(exchange.getRequestMethod())) {
                // Parse request body
                InputStreamReader isr = new InputStreamReader(exchange.getRequestBody(), StandardCharsets.UTF_8);
                BufferedReader br = new BufferedReader(isr);
                StringBuilder requestBody = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) {
                    requestBody.append(line);
                }
                // Parse JSON body using Gson
                Gson gson = new Gson();
                AuthRequest request = gson.fromJson(requestBody.toString(), AuthRequest.class);
                String path = "secret/kv/data/" + request.getUsername();
                // Check if the user is already registered
                String storedSecretKey = null;
                try {
                    storedSecretKey = Utils.getSecretKeyForUser(path);
                } catch (VaultException e) {
                    throw new RuntimeException(e);
                }
                if (storedSecretKey != null) {
                    // User already registered, return existing secret key
                    String response = "{\"success\": true, \"secretKey\": \"" + storedSecretKey + "\"}";
                    exchange.getResponseHeaders().add("Content-Type", "application/json");
                    exchange.sendResponseHeaders(200, response.length());
                    OutputStream os = exchange.getResponseBody();
                    os.write(response.getBytes());
                    os.close();
                } else {
                    // Perform authentication (replace this with your actual authentication logic)
                    if ("username".equals(request.getUsername()) && "password".equals(request.getPassword())) {
                        String secretKey = Utils.generateSecretKey(); // Generate a new secret key
                        // Store secretKey securely in Vault
                        Utils.storeSecretKeyForUser(request.getUsername(), secretKey);

                        String response = "{\"success\": true, \"secretKey\": \"" + secretKey + "\"}";
                        exchange.getResponseHeaders().add("Content-Type", "application/json");
                        exchange.sendResponseHeaders(200, response.length());
                        OutputStream os = exchange.getResponseBody();
                        os.write(response.getBytes());
                        os.close();
                    } else {
                        String response = "{\"success\": false, \"message\": \"Invalid username or password.\"}";
                        exchange.getResponseHeaders().add("Content-Type", "application/json");
                        exchange.sendResponseHeaders(401, response.length());
                        OutputStream os = exchange.getResponseBody();
                        os.write(response.getBytes());
                        os.close();
                    }
                }
            } else {
                exchange.sendResponseHeaders(405, 0); // Method Not Allowed
                exchange.close();
            }
        }
    }

    static class VerifyOTPHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("POST".equals(exchange.getRequestMethod())) {
                // Parse request body
                InputStreamReader isr = new InputStreamReader(exchange.getRequestBody(), StandardCharsets.UTF_8);
                BufferedReader br = new BufferedReader(isr);
                StringBuilder requestBody = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) {
                    requestBody.append(line);
                }
                // Parse JSON body using Gson
                Gson gson = new Gson();
                VerifyOTPRequest request = gson.fromJson(requestBody.toString(), VerifyOTPRequest.class);
                String path = "secret/kv/data/" + request.getUsername();
                // Retrieve the stored secret key for the user
                String storedSecretKey = null;
                try {
                    storedSecretKey = Utils.getSecretKeyForUser(path);
                } catch (VaultException e) {
                    throw new RuntimeException(e);
                }

                // Perform OTP verification using the secret key and OTP code
                boolean verified = Utils.verifyCode(storedSecretKey, request.getOtp());
                String response;
                if (verified) {
                    response = "{\"success\": true}";
                    exchange.getResponseHeaders().add("Content-Type", "application/json");
                    exchange.sendResponseHeaders(200, response.length());
                } else {
                    response = "{\"success\": false}";
                    exchange.getResponseHeaders().add("Content-Type", "application/json");
                    exchange.sendResponseHeaders(401, response.length());
                }
                OutputStream os = exchange.getResponseBody();
                os.write(response.getBytes());
                os.close();
            } else {
                exchange.sendResponseHeaders(405, 0); // Method Not Allowed
                exchange.close();
            }
        }
    }

    static class BarcodeHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("GET".equals(exchange.getRequestMethod())) {
                // Parse the query parameters to get the secretKey and username
                String query = exchange.getRequestURI().getQuery();
                Map<String, String> params = queryToMap(query);
                String secretKey = params.get("secretKey");
                String username = params.get("username");

                if (secretKey != null && !secretKey.isEmpty() && username != null && !username.isEmpty()) {
                    // Generate the barcode image using the secret key
                    String barcodeData = null;
                    try {
                        barcodeData = Utils.getGoogleAuthenticatorBarCode(username);
                    } catch (VaultException e) {
                        throw new RuntimeException(e);
                    }
                    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                    try {
                        Utils.createQRCode(barcodeData, outputStream, 400, 400);
                    } catch (WriterException e) {
                        logger.error("Error creating QR code", e);
                        exchange.sendResponseHeaders(500, -1);
                        return;
                    }

                    // Set response headers
                    exchange.getResponseHeaders().set("Content-Type", "image/png");
                    exchange.sendResponseHeaders(200, outputStream.size());

                    // Write image to response body
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(outputStream.toByteArray());
                    }
                } else {
                    // Bad request if secretKey or username is not provided
                    exchange.sendResponseHeaders(400, -1);
                }
            } else {
                // Method Not Allowed
                exchange.sendResponseHeaders(405, -1);
            }
        }

        // Helper method to parse query parameters
        private Map<String, String> queryToMap(String query) {
            Map<String, String> result = new HashMap<>();
            if (query != null) {
                for (String param : query.split("&")) {
                    String[] entry = param.split("=");
                    if (entry.length > 1) {
                        result.put(entry[0], entry[1]);
                    }
                }
            }
            return result;
        }
    }

    static class VerifyOTPRequest {
        private String username;
        private int otp;

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public int getOtp() {
            return otp;
        }

        public void setOtp(int otp) {
            this.otp = otp;
        }
    }

    static class AuthRequest {
        private String username;
        private String password;

        public String getUsername() {
            return username;
        }

        public String getPassword() {
            return password;
        }
    }
}
