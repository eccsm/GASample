package net.casim.utils;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.bettercloud.vault.response.LogicalResponse;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import org.apache.commons.codec.binary.Base32;
import org.apache.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

public class Utils {

    private static final Logger logger = LoggerFactory.getLogger(Utils.class);
    private static Vault vault;

    static {
        try {
            VaultConfig config = new VaultConfig()
                    .address(System.getenv("VAULT_ADDR"))
                    .token(System.getenv("VAULT_TOKEN"))
                    .build();

            vault = new Vault(config);
            logger.info("Vault initialized successfully.");
        } catch (VaultException e) {
            logger.error("Error initializing Vault", e);
        }
    }

    public static String getGoogleAuthenticatorBarCode(String username) throws VaultException {
        String path = "secret/kv/data/" + username;
        String secretKey = getSecretKeyForUser(path);
        if (secretKey == null) {
            secretKey = generateSecretKey();
            storeSecretKeyForUser(username, secretKey);
        }
        return generateBarCode(username, secretKey);
    }

    private static String generateBarCode(String username, String secretKey) {
        return "otpauth://totp/"
                + URLEncoder.encode("eccsm-sample" + ":" + username, StandardCharsets.UTF_8).replace("+", "%20")
                + "?secret=" + URLEncoder.encode(secretKey, StandardCharsets.UTF_8).replace("+", "%20")
                + "&issuer=" + URLEncoder.encode("eccsm-sample", StandardCharsets.UTF_8).replace("+", "%20");
    }

    public static void createQRCode(String barCodeData, ByteArrayOutputStream outputStream, int height, int width)
            throws WriterException, IOException {
        BitMatrix matrix = new MultiFormatWriter().encode(barCodeData, BarcodeFormat.QR_CODE, width, height);
        MatrixToImageWriter.writeToStream(matrix, "png", outputStream);
    }

    public static boolean verifyCode(String secretKey, int code) {
        GoogleAuthenticator gAuth = new GoogleAuthenticator();
        return gAuth.authorize(secretKey, code);
    }

    public static String generateSecretKey() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[20];
        random.nextBytes(bytes);
        Base32 base32 = new Base32();
        String secretKey = base32.encodeToString(bytes);
        logger.info("Generated secret key: {}", secretKey);
        return secretKey;
    }

    public static void storeSecretKeyForUser(String username, String secretKey) {
        try {
            String path = "secret/kv/data/" + username;

            LogicalResponse writeResponse = vault.logical()
                    .write(path, new HashMap<String, Object>() {{
                        put("data", new HashMap<String, Object>() {{
                            put("key", Utils.generateSecretKey());
                        }});
                    }});

            if (writeResponse.getRestResponse().getStatus() == HttpStatus.SC_OK)
                logger.info("Stored secret key for user {}: {}", username, secretKey);
            else
                logger.error("Error Occurred, Http Status is {}", writeResponse.getRestResponse().getStatus());

        } catch (VaultException e) {
            logger.error("Error storing secret key for user: {}", username, e);
        }
    }

    public static String getSecretKeyForUser(String path) throws VaultException {
        LogicalResponse readResponse = vault.logical()
                .read(path);
        Map<String, String> data = readResponse.getData();
        String nestedDataJson = data.get("data");

        // Remove braces and split by comma
        nestedDataJson = nestedDataJson.substring(1, nestedDataJson.length() - 1);
        Map<String, String> nestedDataMap = new HashMap<>();
        for (String entry : nestedDataJson.split(",")) {
            String[] keyValue = entry.split("=");
            nestedDataMap.put(keyValue[0].trim(), keyValue[1].trim());
        }

        return nestedDataMap.get("key");

    }
}
