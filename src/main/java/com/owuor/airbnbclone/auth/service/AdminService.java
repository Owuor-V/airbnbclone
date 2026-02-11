package com.owuor.airbnbclone.auth.service;

import com.owuor.airbnbclone.auth.entity.AdminEntity;
import com.owuor.airbnbclone.common.config.entity.PasswordPolicy;
import com.owuor.airbnbclone.common.config.entity.SessionTimeMgt;
import com.owuor.airbnbclone.common.config.entity.TrackAdminLogin;
import com.owuor.airbnbclone.auth.repository.AdminRepository;
import com.owuor.airbnbclone.common.config.repository.SessionTimeMgtRepository;
import com.owuor.airbnbclone.common.config.repository.TrackAdminLoginRepository;
import com.owuor.airbnbclone.common.exception.IncorrectPasswordException;
import com.owuor.airbnbclone.common.requests.AdminRequest;
import com.owuor.airbnbclone.common.requests.LoginRequest;
import com.owuor.airbnbclone.common.responses.AdminResponses;
import com.owuor.airbnbclone.common.responses.AuthResponse;
import com.owuor.airbnbclone.common.responses.GenerateTokenResponse;
import com.owuor.airbnbclone.enumlist.SessionFlag;
import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.SessionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.security.auth.login.AccountLockedException;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@AllArgsConstructor
@NoArgsConstructor
@Slf4j
public class AdminService {

    @Autowired
    private AdminRepository adminRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private PasswordPolicyService passwordPolicyService;
    @Autowired
    private TemporaryPasswordService temporaryPasswordService;
    private static final String REDIS_PREFIX = "user:sessions:";
    @Autowired
    private RedisTemplate<String, String> redisTemplate;
    @Autowired
    private TrackAdminLoginRepository trackAdminLoginRepository;
    @Autowired
    private SessionTimeMgtRepository sessionTimeMgtRepository;
    private static final String adminFlag = "Admin";

    public ResponseEntity<AdminResponses> createAdmin(AdminRequest adminRequest) {

        if (adminRepository.existsByUserId(adminRequest.getUserId())) {
            throw new IllegalArgumentException("User Id already exists");
        }

        if (adminRepository.existsByEmployeeId(adminRequest.getEmployeeId())) {
            throw new IllegalArgumentException("Employee Id already exists");
        }

        AdminEntity adminEntity = new AdminEntity();
        adminEntity.setUserId(adminRequest.getUserId());
        adminEntity.setAdminName(adminRequest.getAdminName());
        adminEntity.setEmail(adminRequest.getEmail());
        adminEntity.setEmployeeId(adminRequest.getEmployeeId());
        adminEntity.setPhoneNumber(adminRequest.getPhoneNumber());

        AdminEntity savedAdmin = adminRepository.save(adminEntity);

        AdminResponses response = new AdminResponses();
        response.setUserId(savedAdmin.getUserId());
        response.setAdminName(savedAdmin.getAdminName());
        response.setEmail(savedAdmin.getEmail());
        response.setEmployeeId(savedAdmin.getEmployeeId());
        response.setPhoneNumber(savedAdmin.getPhoneNumber());

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    public AdminResponses login(LoginRequest request,
                                HttpServletResponse servletResponse,
                                HttpServletRequest servletRequest)
            throws AccountLockedException, EntityNotFoundException, IOException {

        Optional<AdminEntity> userOpt = adminRepository.findByUserId(request.getUserId());
        if (userOpt.isEmpty()) {
            throw new EntityNotFoundException("Admin with that userId is not found.");
        }

        AdminEntity adminEntity = userOpt.get();

        // Check account status
        if (adminEntity.getAccountLocked()) {
            log.warn("Authentication attempt for locked account: {}", adminEntity.getUserId());
            throw new AccountLockedException("Account is locked. Please contact the Administrator");
        }
        if (adminEntity.getIsDeleted()) {
            log.warn("Authentication attempt for deleted account: {}", adminEntity.getUserId());
            throw new EntityNotFoundException("Admin not found");
        }

        // Check password
        if (!passwordEncoder.matches(request.getPassword(), adminEntity.getPassword())) {
            adminEntity.incrementFailedAttempts();
            adminRepository.save(adminEntity);

            PasswordPolicy passwordPolicy = passwordPolicyService.getAdminPasswordPolicy();
            int maxAllowedAttempts = passwordPolicy.getMaxLoginAttempts();

            if (adminEntity.getFailedLoginAttempts() >= maxAllowedAttempts) {
                adminEntity.setAccountLocked(true);
                adminRepository.save(adminEntity);
                log.warn("Account locked due to multiple failed login attempts for admin: {}", adminEntity.getUserId());
                throw new AccountLockedException("Account " + adminEntity.getUserId() + " locked due to multiple failed login attempts.");
            }

            if (isPasswordResetRequiredForUser(adminEntity)) {
                sendPassword(adminEntity.getUserId());
                // You cannot set response message here; controller can handle that if needed
            }

            log.info("Incorrect password attempt for admin: {}. Failed attempts: {}", adminEntity.getUserId(), adminEntity.getFailedLoginAttempts());
            throw new IncorrectPasswordException("Incorrect password/email for account " + adminEntity.getUserId() + ". Failed attempts: " + adminEntity.getFailedLoginAttempts());
        }

        // Password correct — record login
        recordAdminLogin(adminEntity);

        String jti = getAdminRandomUUID();

        Optional<SessionTimeMgt> optSessionTime = sessionTimeMgtRepository.findBySessionFlag(SessionFlag.valueOf(adminFlag));
        if (optSessionTime.isEmpty()){
            throw new SessionException("Session Time not found.");
        }

        revokeAllUserTokens(adminEntity);
        GenerateTokenResponse generateTokenResponse =
                jwtService.generateToken(adminEntity, servletRequest, sessionTimeMgt.getAccessTokenExpiryTime(), jti);

        // Build response
        AdminLoginResponse loginResponse = AdminLoginResponse.builder()
                .userId(adminEntity.getUserId())
                .accessToken(generateTokenResponse.getToken())
                .adminName(adminEntity.getAdminName())
                .email(adminEntity.getEmail())
                .firstLogin(adminEntity.getFirstLogin())
                .accountLocked(adminEntity.getAccountLocked())
                .roles(adminEntity.getRole() == null ? Collections.emptyList() :
                        Collections.singletonList(
                                RoleResponse.builder()
                                        .name(adminEntity.getRole().getName())
                                        .permissions(adminEntity.getRole().getPermissions().stream()
                                                .map(p -> PermissionResponse.builder()
                                                        .name(p.getName())
                                                        .build())
                                                .collect(Collectors.toList()))
                                        .build()))
                .sessionId(String.valueOf(generateTokenResponse.getJti()))
                .sessionExpirationTime(generateTokenResponse.getExpiresOn())
                .build();

        // Return the response DTO directly — controller will wrap in ResponseEntity
        return AdminResponses.builder()
                .message(adminEntity.getFirstLogin() ? "First login detected. Please reset your password." : "Success")
                .data(loginResponse)
                .build();
    }

    public String getAdminRandomUUID(){
        return UUID.randomUUID().toString();

    }

    private void revokeAllUserTokens (AdminEntity adminEntity){
        String activeJtiKey = REDIS_PREFIX + adminEntity.getUserId() + ":activeJTI";
        String jti = redisTemplate.opsForValue().get(activeJtiKey);
        if (jti != null) {
            jwtService.invalidateSession(adminEntity.getUserId(), jti);
            log.info("User {} has logged out and session {} invalidated.", adminEntity.getUserId(), jti);
        }
    }


    @Transactional
    public void recordAdminLogin(AdminEntity adminEntity) {
        TrackAdminLogin login = new TrackAdminLogin();
        login.setUserId(adminEntity.getUserId());
        login.setLoginTime(LocalDateTime.now());
        trackAdminLoginRepository.save(login);
    }

    public boolean isPasswordResetRequiredForUser(AdminEntity adminEntity) {

        PasswordPolicy passwordPolicy =
                passwordPolicyService.getAdminPasswordPolicy();

        int passwordExpiryDays = passwordPolicy.getPasswordExpiryDays();

        LocalDateTime expiryDate =
                adminEntity.getPasswordLastUpdated().plusDays(passwordExpiryDays);

        return LocalDateTime.now().isAfter(expiryDate);
    }

    public AuthResponse sendPassword(String userId)
            throws EntityNotFoundException {

        AdminEntity adminEntity = adminRepository.findByUserId(userId)
                .orElseThrow(() ->
                        new EntityNotFoundException("Admin with userId " + userId + " not found."));

        String email = adminEntity.getEmail();
        String generatedPassword = temporaryPasswordService.generateSecurePassword();

        adminEntity.setPassword(passwordEncoder.encode(generatedPassword));
        adminEntity.setFirstLogin(Boolean.TRUE);
        adminEntity.setPasswordLastUpdated(LocalDateTime.now());
        adminRepository.save(adminEntity);

//        PasswordResetNotification passwordResetNotification =
//                PasswordResetNotification.builder()
//                        .email(email)
//                        .password(generatedPassword)
//                        .build();
//
//        authenticationProducer.sendPasswordResetNotification(passwordResetNotification);

        log.info("Password sent successfully to email: {}", email);

        return AuthResponse.builder()
                .userId(adminEntity.getUserId())
                .build();
    }



}
