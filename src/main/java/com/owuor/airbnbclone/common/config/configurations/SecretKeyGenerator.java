package com.owuor.airbnbclone.common.config.configurations;

import com.owuor.airbnbclone.common.config.repository.SecretKeyGenerationRepository;
import com.owuor.airbnbclone.common.config.service.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Component
public class SecretKeyGenerator implements CommandLineRunner {
    private static final String MASTER_KEY_REDIS_KEY = "encryption:masterKey";
    private final DateTimeFormatter formatter = DateTimeFormatter.ISO_LOCAL_DATE_TIME;
    private static final String LAST_GENERATED_TIME_KEY = "secretKey:lastGeneratedTime";
    private final JwtService jwtService;
    @Autowired
    private RedisTemplate<String, String> redisTemplate;
    private static final Long SECRET_KEY_ID = 1L;
    @Autowired
    private SecretKeyGenerationRepository secretKeyGenerationRepository;

    public SecretKeyGenerator(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    public void run(String... args) throws Exception {
        getOrGenerateMasterKey();
        //generateAndStoreKeys();
        LocalDateTime lastGeneratedTime = getLastGeneratedTime(); // Implement this to retrieve the last generated time
        LocalDateTime currentTime = LocalDateTime.now();

        if (lastGeneratedTime == null || ChronoUnit.HOURS.between(lastGeneratedTime, currentTime) >= 24){
            generateAndStoreKeys();
            updateLastGeneratedTime(currentTime);
        }

    }

    public Map<String, String> generateSecrets() {
        Map<String, String> secrets = new HashMap<>();

        // Generate an encryption key (128 bits)
        String encryptionKey = generateEncryptionKey();
        secrets.put("encryption-key", encryptionKey);

        // Generate a secret key (256 bits)
        String secretKey = generateSecretKey();
        secrets.put("secret-key", secretKey);

        return secrets;
    }

    private String generateEncryptionKey() {
        try {
            // Generate a 128-bit (16 bytes) AES encryption key
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128, new SecureRandom()); // Use 128 bits for encryption key
            Key key = keyGen.generateKey();
            return bytesToHex(key.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to generate encryption key", e);
        }
    }

    private String generateSecretKey() {
        try {
            // Generate a 256-bit (32 bytes) secret key
            byte[] secretKey = new byte[32]; // 256 bits = 32 bytes
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(secretKey);
            return bytesToHex(secretKey);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate secret key", e);
        }
    }

    // Helper method to convert byte array to hex string
    private String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xFF & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString().toUpperCase(); // Convert to upper case for consistency
    }
    private String getOrGenerateMasterKey() {
        String storedMasterKey = getMasterKey();
        if (storedMasterKey == null) {
            storedMasterKey = generateMasterKey();
            storeMasterKeyInRedis(storedMasterKey);
        }
        return storedMasterKey;
    }
    private void storeMasterKeyInRedis(String masterKey) {
        // Store the master key in Redis
        redisTemplate.opsForValue().set(MASTER_KEY_REDIS_KEY, masterKey);
    }

    private String generateMasterKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256); // Using AES 256-bit for strong encryption
            SecretKey secretKey = keyGen.generateKey();
            return Base64.getEncoder().encodeToString(secretKey.getEncoded());
        } catch (Exception e) {
            throw new RuntimeException("Error generating master key", e);
        }
    }

    public String getMasterKey() {
        return redisTemplate.opsForValue().get(MASTER_KEY_REDIS_KEY);
    }
    private void generateAndStoreKeys() {
        Map<String, String> secrets = generateSecrets();
        String encryptionKey = secrets.get("encryption-key");
        String secretKey = secrets.get("secret-key");
        System.out.println("SYSTEM GENERATED KEYS");

        String encryptedEncryptionKey = encrypt(encryptionKey);
        String encryptedSecretKey = encrypt(secretKey);

        redisTemplate.opsForValue().set("jwt:encryptionKey", encryptedEncryptionKey);
        redisTemplate.opsForValue().set("jwt:secretKey", encryptedSecretKey);
    }

    public String retrieveEncryptionKey() {
        String encryptedKey = redisTemplate.opsForValue().get("jwt:encryptionKey");
        return decrypt(encryptedKey);
    }

    public String retrieveSecretKey() {
        String encryptedKey = redisTemplate.opsForValue().get("jwt:secretKey");
        return decrypt(encryptedKey);
    }

    private String encrypt(String value) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            SecretKeySpec secretKeySpec = new SecretKeySpec(Base64.getDecoder().decode(getMasterKey()), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            return Base64.getEncoder().encodeToString(cipher.doFinal(value.getBytes()));
        } catch (Exception e) {
            throw new RuntimeException("Error while encrypting", e);
        }
    }

    private String decrypt(String encryptedValue) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            SecretKeySpec secretKeySpec = new SecretKeySpec(Base64.getDecoder().decode(getMasterKey()), "AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedValue)));
        } catch (Exception e) {
            throw new RuntimeException("Error while decrypting", e);
        }
    }
    private LocalDateTime getLastGeneratedTime() {
        // Retrieve the last generated time from Redis
        String lastGeneratedTimeStr = redisTemplate.opsForValue().get(LAST_GENERATED_TIME_KEY);
        return lastGeneratedTimeStr != null ? LocalDateTime.parse(lastGeneratedTimeStr, formatter) : null;
    }

    private void updateLastGeneratedTime(LocalDateTime currentTime) {
        // Update the last generated time in Redis
        String currentTimeStr = currentTime.format(formatter);
        redisTemplate.opsForValue().set(LAST_GENERATED_TIME_KEY, currentTimeStr);
    }
}
