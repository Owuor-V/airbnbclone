package com.owuor.airbnbclone.common.config.service;

import com.owuor.airbnbclone.auth.entity.AdminEntity;
import com.owuor.airbnbclone.auth.entity.ClientEntity;
import com.owuor.airbnbclone.auth.repository.AdminRepository;
import com.owuor.airbnbclone.auth.repository.ClientRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.client.RestTemplate;

import java.util.List;

@Configuration
@EnableJpaAuditing(auditorAwareRef = "springSecAuditorAware")
public class ApplicationConfig {

    private final AdminRepository adminRepository;
    private final ClientRepository clientRepository;


    public ApplicationConfig(AdminRepository adminRepository, ClientRepository clientRepository) {
        this.adminRepository = adminRepository;
        this.clientRepository = clientRepository;
    }
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

//    @Bean
//    public AuditorAware<String> springSecAuditorAware() {
//        return new SpringSecAuditorAware();
//    }
    @Bean
    public UserDetailsService userDetailsService() {
        return userId -> {
            if (isAdminUser(userId)) {
                AdminEntity adminEntity = adminRepository.findByUserId(userId)
                        .orElseThrow(() -> new UsernameNotFoundException("Admin not found"));
                return new org.springframework.security.core.userdetails.User(
                        adminEntity.getUserId(),
                        adminEntity.getPassword(),
                        List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))
                );

            } else {
                ClientEntity clientEntity = clientRepository.findByUserId(userId)
                        .orElseThrow(() -> new UsernameNotFoundException("Customer not found"));
                // Assuming you have similar methods in Customer entity for authorities
                return new org.springframework.security.core.userdetails.User(
                        clientEntity.getUserId(),
                        clientEntity.getPassword(),
                        List.of(new SimpleGrantedAuthority("ROLE_CLIENT"))
                );
            }
        };
    }

    private boolean isAdminUser(String username) {
        // Logic to determine if the user is an adminEntity
        AdminEntity adminEntity = adminRepository.findByUserId(username).orElse(null);
        return adminEntity != null && adminEntity.isAdmin();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
