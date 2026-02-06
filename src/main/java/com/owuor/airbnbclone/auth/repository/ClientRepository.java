package com.owuor.airbnbclone.auth.repository;

import com.owuor.airbnbclone.auth.entity.ClientEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ClientRepository extends JpaRepository<ClientEntity, Long> {
}
