package com.owuor.airbnbclone.auth.repository;

import com.owuor.airbnbclone.auth.entity.AdminEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AdminRepository extends JpaRepository<AdminEntity, Long> {

//    Optional<AdminEntity> findByUserId(String userId);
//
//    boolean existsByemployeeId(Integer employeeId);

    boolean existsByUserId(String userId);

    boolean existsByEmployeeId(Integer employeeId);
}
