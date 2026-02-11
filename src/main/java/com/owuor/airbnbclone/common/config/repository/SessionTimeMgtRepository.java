package com.owuor.airbnbclone.common.config.repository;

import com.owuor.airbnbclone.common.config.entity.SessionTimeMgt;
import com.owuor.airbnbclone.enumlist.SessionFlag;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface SessionTimeMgtRepository extends JpaRepository<SessionTimeMgt, Long> {

    Optional<SessionTimeMgt> findBySessionFlag(SessionFlag sessionFlag);
    boolean existsBySessionFlag(SessionFlag sessionFlag);
}
