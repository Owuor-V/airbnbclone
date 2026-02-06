package com.owuor.airbnbclone.auth.entity;

import com.owuor.airbnbclone.auditable.Auditable;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

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
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(name = "user_id", nullable = false, unique = true)
    private String userId;
    @Column( length = 50)
    private Integer employeeId;
    private String adminName;
    private String phoneNumber;
    @Column(unique = true)
    private String email;
    @Builder.Default
    @Column(name = "is_deleted", nullable = false, columnDefinition = "boolean default false")
    private Boolean isDeleted = false;
    private boolean isAdmin;
    private String password;

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

}
