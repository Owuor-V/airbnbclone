package com.owuor.airbnbclone.auth.service;

import com.owuor.airbnbclone.common.config.entity.PasswordPolicy;
import com.owuor.airbnbclone.common.config.repository.PasswordPolicyRepository;
import com.owuor.airbnbclone.common.dto.PasswordPolicyDto;
import com.owuor.airbnbclone.enumlist.PasswordEnum;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class PasswordPolicyService {

    private PasswordPolicyRepository passwordPolicyRepository;
//    private String success="Success";

    public PasswordPolicy setAdminPasswordPolicy(PasswordPolicyDto policy) {
        Optional<PasswordPolicy> optionalPasswordPolicy =
                passwordPolicyRepository.findByPasswordEnum(PasswordEnum.ADMIN);

        PasswordPolicy passwordPolicy = optionalPasswordPolicy
                .orElseGet(PasswordPolicy::new);

        if (optionalPasswordPolicy.isEmpty()) {
            throw new RuntimeException("Admin Password Policy Not Found");
        }

        passwordPolicy.setPasswordEnum(PasswordEnum.ADMIN);
        passwordPolicy.setMaxLength(policy.getMaxLength());
        passwordPolicy.setMinLength(policy.getMinLength());
        passwordPolicy.setRequireDigits(policy.isRequireDigits());
        passwordPolicy.setRequireUppercase(policy.isRequireUppercase());
        passwordPolicy.setRequireLowercase(policy.isRequireLowercase());
        passwordPolicy.setRequireSpecialChars(policy.isRequireSpecialChars());
        passwordPolicy.setPasswordExpiryDays(policy.getPasswordExpiryDays());
        passwordPolicy.setMaxLoginAttempts(policy.getMaxLoginAttempts());

        return passwordPolicyRepository.save(passwordPolicy);

    }

    public PasswordPolicy getAdminPasswordPolicy() {

        return passwordPolicyRepository
                .findByPasswordEnum(PasswordEnum.ADMIN)
                .orElseThrow(() ->
                        new RuntimeException("Admin Password Policy Not Found"));
    }

}
