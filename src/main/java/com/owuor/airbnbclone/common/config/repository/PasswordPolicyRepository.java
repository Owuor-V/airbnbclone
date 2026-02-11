package com.owuor.airbnbclone.common.config.repository;

import com.owuor.airbnbclone.common.config.entity.PasswordPolicy;
import com.owuor.airbnbclone.enumlist.PasswordEnum;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface PasswordPolicyRepository extends JpaRepository<PasswordPolicy, Long> {
    Optional<PasswordPolicy> findByPasswordEnum(PasswordEnum passwordEnum);
}
