package com.owuor.airbnbclone.auth.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.Base64;

@Service
@Slf4j
public class TemporaryPasswordService {
    public String generateSecurePassword() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[8]; // Adjusted to 8 bytes for a longer password
        random.nextBytes(bytes);
        String password = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        return password;
    }
}
