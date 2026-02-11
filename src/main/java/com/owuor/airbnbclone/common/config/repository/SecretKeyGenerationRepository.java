package com.owuor.airbnbclone.common.config.repository;

import com.owuor.airbnbclone.common.config.entity.SecretKeyGeneration;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SecretKeyGenerationRepository extends JpaRepository<SecretKeyGeneration, Long> {
}
