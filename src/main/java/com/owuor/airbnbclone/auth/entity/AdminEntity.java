package com.owuor.airbnbclone.auth.entity;

import com.owuor.airbnbclone.auditable.Auditable;
import com.owuor.airbnbclone.enumlist.PinOtpAdmin;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Entity
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Data
public class AdminEntity extends Auditable<String> implements UserDetails {

    @Id
    @Column(name = "user_id", nullable = false, unique = true)
    private String userId;
    @Column( name = "admin_name")
    private String adminName;
    private String password;
    private String phoneNumber;
    private String email;
    private int failedLoginAttempts;
    private boolean accountLocked;
    private boolean isAdmin;
    @Column(name = "first_login")
    private Boolean firstLogin;
    @Column(name = "set_biometrics")
    private Boolean setBiometrics;
    @Column(name = "is_deleted", nullable = false, columnDefinition = "boolean default false")
    private Boolean isDeleted;
    private boolean active;
    private Integer pin;
    @Enumerated(EnumType.STRING)
    private PinOtpAdmin pinOtpAdminCheck;
    private LocalDateTime passwordLastUpdated;
    private String employeeId;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> authorities = new ArrayList<>();

//        // Ensure the role is initialized
//        if (role != null) {
//            authorities.add(new SimpleGrantedAuthority(role.getName()));
//            for (Permission permission : role.getPermissions()) {
//                authorities.add(new SimpleGrantedAuthority(permission.getName()));
//            }
//        }

        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return userId;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    public boolean getAccountLocked() {
        return accountLocked;
    }

    public void resetFailedAttempts() {
        this.failedLoginAttempts = 0;
    }



    public void unlockAccount() {
        this.setAccountLocked(false);
    }


    public void incrementFailedAttempts() {
        this.failedLoginAttempts++;
    }

}
