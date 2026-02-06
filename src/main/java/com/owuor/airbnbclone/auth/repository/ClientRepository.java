package com.owuor.airbnbclone.auth.repository;

import com.owuor.airbnbclone.auth.entity.AdminEntity;
import com.owuor.airbnbclone.auth.entity.ClientEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ClientRepository extends JpaRepository<ClientEntity, Long> {

    Optional<ClientEntity> findByUserId(String userId);
}
