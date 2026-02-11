package com.owuor.airbnbclone.common.config.entity;


import com.owuor.airbnbclone.enumlist.PasswordEnum;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
public class PasswordPolicy {

    @Id
    @Enumerated(EnumType.STRING)
    private PasswordEnum passwordEnum;
    private int minLength;
    private int maxLength;
    private boolean requireUppercase;
    private boolean requireLowercase;
    private boolean requireDigits;
    private boolean requireSpecialChars;
    private int passwordExpiryDays;
    private int maxLoginAttempts;
}
