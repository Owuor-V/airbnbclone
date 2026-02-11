package com.owuor.airbnbclone.common.config.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.owuor.airbnbclone.auth.entity.ClientEntity;
import com.owuor.airbnbclone.common.config.configurations.SecretKeyGenerator;
import com.owuor.airbnbclone.common.config.entity.SessionTimeMgt;
import com.owuor.airbnbclone.common.config.repository.SecretKeyGenerationRepository;
import com.owuor.airbnbclone.common.config.repository.SessionTimeMgtRepository;
import com.owuor.airbnbclone.common.responses.GenerateTokenResponse;
import com.owuor.airbnbclone.enumlist.SessionFlag;
import io.jsonwebtoken.Claims;
import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service

public class JwtService {

    private static final Logger logger = LoggerFactory.getLogger(JwtService.class);
    @Autowired
    private SecretKeyGenerationRepository secretKeyGenerationRepository;
    private static final Long SECRET_KEY_ID = 1L;
    private static final String customerFlag="Customer";
    private static final String adminFlag = "Admin";
    private  final SessionTimeMgtRepository sessionTimeMgtRepository;
    @Autowired
    private RedisTemplate<String, String> redisTemplate;

    //private static final String REDIS_PREFIX = "user:";
    private static final String REDIS_PREFIX = "user:sessions:";
    private final SecretKeyGenerator secretKeyGenerator;

    private long refreshExpiration;

    public JwtService(SessionTimeMgtRepository sessionTimeMgtRepository, SecretKeyGenerator secretKeyGenerator) {
        this.sessionTimeMgtRepository = sessionTimeMgtRepository;

        this.secretKeyGenerator = secretKeyGenerator;
    }


    public SessionTimeMgt getCustomerSession (){
        Optional<SessionTimeMgt> sessionTimeMgt=sessionTimeMgtRepository.findBySessionFlag(SessionFlag.valueOf(adminFlag));
        if (sessionTimeMgt.isEmpty()) {
            throw new EntityNotFoundException("Customer Session time not found");
        }
        return sessionTimeMgt.get();

    }
    public SessionTimeMgt getAdminSession (){
        Optional<SessionTimeMgt> sessionTimeMgt=sessionTimeMgtRepository.findBySessionFlag(SessionFlag.valueOf(adminFlag));
        if (sessionTimeMgt.isEmpty()) {
            throw new EntityNotFoundException("Admins Session time not found");
        }
        return sessionTimeMgt.get();

    }
    public String retrieveEncryptionKey() throws IOException {
        String encryptedKey = redisTemplate.opsForValue().get("jwt:encryptionKey");
        System.out.println("D");
        String decryptedKey= decrypt(encryptedKey);
        System.out.println("DECRYPTED KEY: "+decryptedKey);
        return decryptedKey;

    }

    public String retrieveSecretKey() throws IOException {
        String encryptedKey = redisTemplate.opsForValue().get("jwt:secretKey");
        return decrypt(encryptedKey);
    }
    private String decrypt(String encryptedValue) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            SecretKeySpec secretKeySpec = new SecretKeySpec(Base64.getDecoder().decode(secretKeyGenerator.getMasterKey()), "AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedValue)));
        } catch (Exception e) {
            throw new RuntimeException("Error while decrypting", e);
        }
    }


    private String compress(String data) throws IOException {
        logger.debug("Compressing data: {}", data);
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        try (GzipCompressorOutputStream gzipStream = new GzipCompressorOutputStream(byteStream)) {
            gzipStream.write(data.getBytes());
        }
        String compressedData = byteStream.toString("ISO-8859-1"); // Convert to a string
        logger.debug("Compressed data: {}", compressedData);
        return compressedData;
    }

    private String decompress(String compressedData) throws IOException {
        logger.debug("Decompressing data: {}", compressedData);
        byte[] bytes = compressedData.getBytes("ISO-8859-1");
        ByteArrayInputStream byteStream = new ByteArrayInputStream(bytes);
        try (InputStream gzipStream = new GzipCompressorInputStream(byteStream)) {
            String decompressedData = new String(gzipStream.readAllBytes());
            logger.debug("Decompressed data: {}", decompressedData);
            return decompressedData;
        }
    }

    public String extractUsername(String token) {
        String username = extractClaim(token, Claims::getSubject);
        logger.debug("Extracted username: {}", username);
        return username;
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        T claim = claimsResolver.apply(claims);
        logger.debug("Extracted claim: {}", claim);
        return claim;
    }

    private Claims extractAllClaims(String token) {
        logger.debug("Attempting to parse JWT: {}", token);

        try {
            // Decrypt the token before parsing
            String decryptedToken = decryptJwt(token);
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(getSignInKey())
                    .build()
                    .parseClaimsJws(decryptedToken)  // Parse the decrypted JWT
                    .getBody();
            logger.debug("Successfully extracted claims: {}", claims);
            return claims;
        } catch ( IOException e) {
            logger.error("Error decrypting or decompressing JWT", e);
            throw new RuntimeException("Failed to decrypt/decompress JWT", e);
        }
    }


    public boolean extractIsAdmin(String token) {
        boolean isAdmin = extractClaim(token, claims -> claims.get("isAdmin", Boolean.class));
        logger.debug("Extracted isAdmin: {}", isAdmin);
        return isAdmin;
    }

    public GenerateTokenResponse generateToken(ClientEntity clientEntity, HttpServletRequest request, Integer expirationTime, String jti) throws JoseException, IOException {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", clientEntity.getUserId());
        claims.put("isAdmin", clientEntity.isAdmin());  // Assuming you still want to include this

         /*   // Handle multiple roles
            List<String> roles = customer.getRoles().stream()
                    .map(Role::getName)
                    .collect(Collectors.toList());

            // Collect permissions from all roles, avoiding duplicates
            List<String> permissions = customer.getRoles().stream()
                    .flatMap(role -> role.getPermissions().stream())  // Extract permissions for each role
                    .map(Permission::getName)
                    .distinct()
                    .collect(Collectors.toList());

            claims.put("roles", roles);
            claims.put("permissions", permissions);*/
        //String jti = UUID.randomUUID().toString();
        claims.put("jti", jti);
        claims.put("deviceInfo", DeviceInfoUtil.getClientDeviceInfo(request));
        long EXPIRATION_TIME_MS=60 * 1000 * Long.valueOf(expirationTime);

        String jwt = buildToken(claims, clientEntity, EXPIRATION_TIME_MS);
        logger.debug("Generated JWT (before encryption): {}", jwt);
        try {
            String encryptedJwt = encryptJwt(jwt);
            logger.debug("Generated JWT (after encryption): {}", encryptedJwt);
            //storeTokenInRedis(customer.getUserId(), jti, EXPIRATION_TIME_MS);
            Map<String,String> sessionData=storeCustomerSessionDataInRedis(clientEntity.getUserId(), jti, EXPIRATION_TIME_MS, request,"Customer",clientEntity);
            return GenerateTokenResponse.builder()
                    .token(encryptedJwt)
                    .jti(jti)
                    .expiresOn(LocalDateTime.parse(sessionData.get("ExpiresAt")))
                    .deviceInfo(sessionData.get("device"))
                    .build();

        } catch (IOException e) {
            logger.error("Error encrypting JWT", e);
            throw new RuntimeException(e);
        }
    }
    public GenerateTokenResponse getToken(Customer customer, HttpServletRequest request, Integer expirationTime, String jti, Role role) throws JoseException, IOException {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", customer.getUserId());
        claims.put("isAdmin", customer.isAdmin());  // Assuming you still want to include this

         /*   // Handle multiple roles
            List<String> roles = customer.getRoles().stream()
                    .map(Role::getName)
                    .collect(Collectors.toList());

            // Collect permissions from all roles, avoiding duplicates
            List<String> permissions = customer.getRoles().stream()
                    .flatMap(role -> role.getPermissions().stream())  // Extract permissions for each role
                    .map(Permission::getName)
                    .distinct()
                    .collect(Collectors.toList());

            claims.put("roles", roles);
            claims.put("permissions", permissions);*/
        //String jti = UUID.randomUUID().toString();
        claims.put("jti", jti);
        claims.put("deviceInfo", DeviceInfoUtil.getClientDeviceInfo(request));
        long EXPIRATION_TIME_MS=60 * 1000 * Long.valueOf(expirationTime);

        String jwt = buildToken(claims, customer, EXPIRATION_TIME_MS);
        logger.debug("Generated JWT (before encryption): {}", jwt);
        try {
            String encryptedJwt = encryptJwt(jwt);
            logger.debug("Generated JWT (after encryption): {}", encryptedJwt);
            //storeTokenInRedis(customer.getUserId(), jti, EXPIRATION_TIME_MS);
            Map<String,String> sessionData=storeCustomerSessionInRedisPerProfile(customer.getUserId(), jti, EXPIRATION_TIME_MS, request,"Customer",role);
            return GenerateTokenResponse.builder()
                    .token(encryptedJwt)
                    .jti(jti)
                    .expiresOn(LocalDateTime.parse(sessionData.get("ExpiresAt")))
                    .deviceInfo(sessionData.get("device"))
                    .build();

        } catch (IOException e) {
            logger.error("Error encrypting JWT", e);
            throw new RuntimeException(e);
        }
    }


    public GenerateTokenResponse generateToken(Admin admin,HttpServletRequest request,Integer expirationTime,String jti) throws JoseException, IOException {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", admin.getUserId());
        claims.put("isAdmin", true);
           /* List<String> roles = Collections.singletonList(admin.getRole().getName());
            List<String> permissions = admin.getRole().getPermissions().stream()
                    .map(Permission::getName)
                    .distinct()
                    .collect(Collectors.toList());
            claims.put("roles", roles);
            claims.put("permissions", permissions);*/
        claims.put("jti", jti);
        claims.put("deviceInfo", DeviceInfoUtil.getClientDeviceInfo(request));
        long EXPIRATION_TIME_MS=60 * 1000 * Long.valueOf(expirationTime);
        String jwt = buildToken(claims, admin, EXPIRATION_TIME_MS);
        logger.debug("Generated JWT (before encryption): {}", jwt);
        try {
            String encryptedJwt = encryptJwt(jwt);
            logger.debug("Generated JWT (after encryption): {}", encryptedJwt);
            Map<String,String> sessionData=storeAdminSessionDataInRedis(admin.getUserId(), jti, EXPIRATION_TIME_MS, request,"Admin",admin);
            return GenerateTokenResponse.builder()
                    .token(encryptedJwt)
                    .jti(jti)
                    .expiresOn(LocalDateTime.parse(sessionData.get("ExpiresAt")))
                    .deviceInfo(sessionData.get("device"))
                    .build();
        } catch (IOException e) {
            logger.error("Error encrypting JWT", e);
            throw new RuntimeException(e);
        }
    }

    public String generateRefreshToken(Customer customer) throws JoseException, IOException {
        String token = buildToken(new HashMap<>(), customer, 60 * 1000 * Long.valueOf(getCustomerSession().getRefreshTokenExpiryTime()));
        logger.debug("Generated refresh token: {}", token);
        return token;
    }

    public String generateRefreshToken(Admin admin) throws JoseException, IOException {
        String token = buildToken(new HashMap<>(), admin, 60 * 1000 * Long.valueOf(getAdminSession().getRefreshTokenExpiryTime()));
        logger.debug("Generated refresh token: {}", token);
        return token;
    }

    private String buildToken(Map<String, Object> extraClaims, Customer customer, long expiration) throws JoseException, IOException {
        String token = Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(customer.getUserId())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
        logger.debug("Built token: {}", token);
        return token;
    }

    private String buildToken(Map<String, Object> extraClaims, Admin admin, long expiration) throws JoseException, IOException {
        String token = Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(admin.getUserId())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
        logger.debug("Built token: {}", token);
        return token;
    }

    private Key getSignInKey() throws JoseException, IOException {
        byte[] keyBytes = Decoders.BASE64.decode(retrieveSecretKey());
        System.out.println("Retrieved Secret Key from Vault service: "+retrieveSecretKey());
        Key key = Keys.hmacShaKeyFor(keyBytes);
        logger.debug("Signing key: {}", key);
        return key;
    }

    public String encryptJwt(String jwt) throws JoseException, IOException {
        String compressedJwt = compress(jwt); // Compress before encryption
        logger.debug("Compressed JWT: {}", compressedJwt);
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setPayload(compressedJwt);
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.DIRECT);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_GCM);
        jwe.setKey(new AesKey(retrieveEncryptionKey().getBytes())); // Use the decoded key
        System.out.println("Retrieved Encryption Key from Vault service: "+retrieveEncryptionKey());
        String encryptedJwt = jwe.getCompactSerialization();
        logger.debug("Encrypted JWT: {}", encryptedJwt);
        return encryptedJwt;
    }

    public String decryptJwt(String jweToken) throws JoseException, IOException {
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setCompactSerialization(jweToken);
        jwe.setKey(new AesKey(retrieveEncryptionKey().getBytes())); // Use the decoded key
        String compressedJwt = jwe.getPayload();
        logger.debug("Decrypted JWT (compressed): {}", compressedJwt);
        String jwt = decompress(compressedJwt); // Decompress after decryption
        logger.debug("Decrypted JWT: {}", jwt);
        return jwt;
    }
    public boolean isTokenValid(String token) {
        Claims claims = extractAllClaims(token);
        String userId = claims.getSubject();
        String jti = claims.getId();

        String redisKey = REDIS_PREFIX + userId + ":activeJTI";
        String storedJti = redisTemplate.opsForValue().get(redisKey);

        // Check if the JTI stored in Redis matches the token's JTI
        return jti.equals(storedJti);
    }
    public String  getJti(String token) {
        Claims claims = extractAllClaims(token);
        String userId = claims.getSubject();
        String redisKey = REDIS_PREFIX + userId + ":activeJTI";
        String storedJti = redisTemplate.opsForValue().get(redisKey);

        // Check if the JTI stored in Redis matches the token's JTI
        return storedJti;
    }
    public boolean isTokenExpired(String token) {
        boolean expired = extractExpiration(token).before(new Date());
        logger.debug("Is token expired: {}", expired);
        return expired;
    }

    public Date extractExpiration(String token) {
        Date expiration = extractClaim(token, Claims::getExpiration);
        logger.debug("Extracted expiration date: {}", expiration);
        return expiration;
    }

    private void storeTokenInRedis(String userId, String jti, long expiration) {
        String redisKey = REDIS_PREFIX + userId + ":activeJTI";

        // Invalidate any previous active JTI for the user
        String previousJti = redisTemplate.opsForValue().get(redisKey);
        if (previousJti != null) {
            redisTemplate.delete(redisKey);
        }

        // Store the new JTI with a TTL matching the JWT expiration
        redisTemplate.opsForValue().set(redisKey, jti, expiration, TimeUnit.MILLISECONDS);
        logger.debug("Stored JTI in Redis with key: {}", redisKey);
        System.out.println("Stored JTI in Redis with key: {}"+ redisKey+jti);
    }
    private Map<String, String> storeCustomerSessionDataInRedis(String userId, String jti, long expiration, HttpServletRequest request, String sessionFlag, Customer customer) {
        String redisKey = REDIS_PREFIX + userId + ":activeJTI";

        // Invalidate previous session to enforce single-session policy
        String previousJti = redisTemplate.opsForValue().get(redisKey);
        if (previousJti != null) {
            invalidateSession(userId, previousJti);
        }

        // Save the new JTI and session data with TTL
        redisTemplate.opsForValue().set(redisKey, jti, expiration, TimeUnit.MILLISECONDS);

        String sessionKey = REDIS_PREFIX + userId + ":session:" + jti;

        // Handle multiple roles
        List<String> roles = customer.getRoles().stream()
                .map(Role::getName)
                .collect(Collectors.toList());

        // Collect permissions from all roles, avoiding duplicates
        List<String> permissions = customer.getRoles().stream()
                .flatMap(role -> role.getPermissions().stream())  // Extract permissions for each role
                .map(Permission::getName)
                .distinct()
                .collect(Collectors.toList());

        Map<String, String> sessionData = new HashMap<>();

        // Use ObjectMapper to serialize lists to JSON
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            // Convert roles and permissions to JSON strings
            sessionData.put("roles", objectMapper.writeValueAsString(roles));  // Serialize List to JSON
            sessionData.put("permissions", objectMapper.writeValueAsString(permissions));  // Serialize List to JSON
        } catch (Exception e) {
            e.printStackTrace();  // Handle any exceptions that occur during serialization
        }

        sessionData.put("jti", jti);
        sessionData.put("UserId", userId);
        sessionData.put("SessionFlag", sessionFlag);
        sessionData.put("createdAt", LocalDateTime.now().toString());
        sessionData.put("ipAddress", getClientIpAddress(request));

        LocalDateTime expiresAt = LocalDateTime.now().plus(Duration.ofMillis(expiration));
        sessionData.put("ExpiresAt", expiresAt.toString());
        sessionData.put("device", DeviceInfoUtil.getClientDeviceInfo(request));

        System.out.println("Device information, ipAddress: " + sessionData.get("ipAddress") + " device: " + sessionData.get("device"));

        redisTemplate.opsForHash().putAll(sessionKey, sessionData);
        redisTemplate.expire(sessionKey, expiration, TimeUnit.MILLISECONDS);

        return sessionData;
    }
    private Map<String, String> storeCustomerSessionInRedisPerProfile(String userId, String jti, long expiration, HttpServletRequest request, String sessionFlag,Role role) {
        String redisKey = REDIS_PREFIX + userId + ":activeJTI";

        // Invalidate previous session to enforce single-session policy
        String previousJti = redisTemplate.opsForValue().get(redisKey);
        if (previousJti != null) {
            invalidateSession(userId, previousJti);
        }

        // Save the new JTI and session data with TTL
        redisTemplate.opsForValue().set(redisKey, jti, expiration, TimeUnit.MILLISECONDS);

        String sessionKey = REDIS_PREFIX + userId + ":session:" + jti;

        // Handle multiple roles
        List<String> roleNames = Collections.singletonList(role.getName());


        // Collect permissions from all roles, avoiding duplicates
        List<String> permissions = role.getPermissions().stream()
                .map(Permission::getName)  // Extract permission names
                .distinct()                // Ensure uniqueness
                .collect(Collectors.toList());
        System.out.println("Permissions attached to token: "+permissions);

        Map<String, String> sessionData = new HashMap<>();

        // Use ObjectMapper to serialize lists to JSON
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            // Convert roles and permissions to JSON strings
            sessionData.put("roles", objectMapper.writeValueAsString(roleNames));  // Serialize List to JSON
            sessionData.put("permissions", objectMapper.writeValueAsString(permissions));  // Serialize List to JSON
        } catch (Exception e) {
            e.printStackTrace();  // Handle any exceptions that occur during serialization
        }

        sessionData.put("jti", jti);
        sessionData.put("UserId", userId);
        sessionData.put("SessionFlag", sessionFlag);
        sessionData.put("createdAt", LocalDateTime.now().toString());
        sessionData.put("ipAddress", getClientIpAddress(request));

        LocalDateTime expiresAt = LocalDateTime.now().plus(Duration.ofMillis(expiration));
        sessionData.put("ExpiresAt", expiresAt.toString());
        sessionData.put("device", DeviceInfoUtil.getClientDeviceInfo(request));

        System.out.println("Device information, ipAddress: " + sessionData.get("ipAddress") + " device: " + sessionData.get("device"));

        redisTemplate.opsForHash().putAll(sessionKey, sessionData);
        redisTemplate.expire(sessionKey, expiration, TimeUnit.MILLISECONDS);

        return sessionData;
    }
    public Collection<? extends GrantedAuthority> getAuthoritiesFromSession(String userId, String jti) {
        List<GrantedAuthority> authorities = new ArrayList<>();
        String sessionKey = REDIS_PREFIX + userId + ":session:" + jti;
        Map<String, String> sessionData = redisTemplate.<String, String>opsForHash().entries(sessionKey);
        // Retrieve the roles and permissions stored in Redis (assumed as JSON)
        String rolesJson = sessionData.get("roles");
        String permissionsJson = sessionData.get("permissions");
        if (rolesJson != null && permissionsJson != null) {
            try {
                ObjectMapper objectMapper = new ObjectMapper();

                // Deserialize JSON strings back to List<String> for roles and permissions
                List<String> roles = objectMapper.readValue(rolesJson, new TypeReference<List<String>>(){});
                List<String> permissions = objectMapper.readValue(permissionsJson, new TypeReference<List<String>>(){});
                for (String role : roles) {
                    authorities.add(new SimpleGrantedAuthority( role));  // Prefix "ROLE_" is standard in Spring Security
                }

                // Add permissions as authorities
                for (String permission : permissions) {
                    authorities.add(new SimpleGrantedAuthority(permission));  // Permissions are added directly as authorities
                }
            } catch (Exception e) {
                e.printStackTrace();  // Handle any exceptions during deserialization
            }
        }
        return authorities;
    }
    private Map<String, String> storeAdminSessionDataInRedis(String userId, String jti, long expiration, HttpServletRequest request, String sessionFlag, Admin admin) {
        String redisKey = REDIS_PREFIX + userId + ":activeJTI";

        // Invalidate previous session to enforce single-session policy
        String previousJti = redisTemplate.opsForValue().get(redisKey);
        if (previousJti != null) {
            invalidateSession(userId, previousJti);
        }

        // Save the new JTI and session data with TTL
        redisTemplate.opsForValue().set(redisKey, jti, expiration, TimeUnit.MILLISECONDS);

        String sessionKey = REDIS_PREFIX + userId + ":session:" + jti;

        // Handle multiple roles
        List<String> roles = Collections.singletonList(admin.getRole().getName());
        List<String> permissions = admin.getRole().getPermissions().stream()
                .map(Permission::getName)
                .distinct()
                .collect(Collectors.toList());

        Map<String, String> sessionData = new HashMap<>();

        // Use ObjectMapper to serialize lists to JSON
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            // Convert roles and permissions to JSON strings
            sessionData.put("roles", objectMapper.writeValueAsString(roles));  // Serialize List to JSON
            sessionData.put("permissions", objectMapper.writeValueAsString(permissions));  // Serialize List to JSON
        } catch (Exception e) {
            e.printStackTrace();  // Handle any exceptions that occur during serialization
        }

        sessionData.put("jti", jti);
        sessionData.put("UserId", userId);
        sessionData.put("SessionFlag", sessionFlag);
        sessionData.put("createdAt", LocalDateTime.now().toString());
        sessionData.put("ipAddress", getClientIpAddress(request));

        LocalDateTime expiresAt = LocalDateTime.now().plus(Duration.ofMillis(expiration));
        sessionData.put("ExpiresAt", expiresAt.toString());
        sessionData.put("device", DeviceInfoUtil.getClientDeviceInfo(request));

        System.out.println("Device information, ipAddress: " + sessionData.get("ipAddress") + " device: " + sessionData.get("device"));

        redisTemplate.opsForHash().putAll(sessionKey, sessionData);
        redisTemplate.expire(sessionKey, expiration, TimeUnit.MILLISECONDS);

        return sessionData;
    }

    public ApiResponse<String> invalidateSession(String userId, String jti) {
        ApiResponse<String> response=new ApiResponse<>();
        String sessionKey = REDIS_PREFIX + userId + ":session:" + jti;
        redisTemplate.delete(sessionKey);

        String activeJtiKey = REDIS_PREFIX + userId + ":activeJTI";
        redisTemplate.delete(activeJtiKey);
        response.setMessage("Session invalidated for user: {}"+ userId);
        logger.debug("Session invalidated for user: {}", userId);
        return response;
    }
    private String getClientIpAddress(HttpServletRequest request) {
        String ipAddress = request.getHeader("X-Forwarded-For");
        if (ipAddress == null || ipAddress.isEmpty()) {
            ipAddress = request.getRemoteAddr();
        }
        return ipAddress;
    }
    public static class DeviceInfoUtil {
        public static String getClientDeviceInfo(HttpServletRequest request) {
            String userAgent = request.getHeader("User-Agent");
            if (userAgent == null || userAgent.isEmpty()) {
                return "Unknown Device";
            }

            if (userAgent.toLowerCase().contains("mobile")) {
                return "Mobile Device - " + getMobileDeviceModel(userAgent);
            } else {
                return "Desktop Device - " + getDesktopDeviceModel(userAgent);
            }
        }

        private static String getMobileDeviceModel(String userAgent) {
            String lowerUserAgent = userAgent.toLowerCase();

            if (lowerUserAgent.contains("iphone")) {
                return getAppleDeviceModel(userAgent);
            } else if (lowerUserAgent.contains("ipad")) {
                return "iPad";
            } else if (lowerUserAgent.contains("android")) {
                return getAndroidDeviceModel(userAgent);
            } else if (lowerUserAgent.contains("windows phone")) {
                return "Windows Phone";
            } else if (lowerUserAgent.contains("blackberry")) {
                return "BlackBerry";
            }
            return "Unknown Mobile Device";
        }

        private static String getDesktopDeviceModel(String userAgent) {
            String lowerUserAgent = userAgent.toLowerCase();

            if (lowerUserAgent.contains("macintosh") || lowerUserAgent.contains("mac os")) {
                if (lowerUserAgent.contains("macbook")) {
                    return "MacBook";
                } else if (lowerUserAgent.contains("imac")) {
                    return "iMac";
                }
                return "Mac Desktop";
            } else if (lowerUserAgent.contains("windows")) {
                if (lowerUserAgent.contains("surface")) {
                    return "Microsoft Surface";
                }
                return "Windows PC";
            } else if (lowerUserAgent.contains("linux")) {
                return "Linux Desktop";
            } else if (lowerUserAgent.contains("chrome os")) {
                return "Chromebook";
            }
            return "Unknown Desktop Device";
        }

        private static String getAppleDeviceModel(String userAgent) {
            if (userAgent.contains("iPhone14")) {
                return "iPhone 14";
            } else if (userAgent.contains("iPhone13")) {
                return "iPhone 13";
            } else if (userAgent.contains("iPhone12")) {
                return "iPhone 12";
            }
            // Add more iPhone models as needed
            return "iPhone";
        }

        private static String getAndroidDeviceModel(String userAgent) {
            if (userAgent.contains("SM-")) {
                return "Samsung Galaxy " + extractModelName(userAgent, "SM-");
            } else if (userAgent.contains("Pixel")) {
                return "Google Pixel";
            } else if (userAgent.contains("OnePlus")) {
                return "OnePlus " + extractModelName(userAgent, "OnePlus");
            }
            return "Android Device";
        }

        private static String extractModelName(String userAgent, String prefix) {
            int startIndex = userAgent.indexOf(prefix);
            if (startIndex == -1) return "Unknown Model";

            int endIndex = userAgent.indexOf(" ", startIndex);
            if (endIndex == -1) endIndex = userAgent.length();

            return userAgent.substring(startIndex, endIndex);
        }
    }

}
