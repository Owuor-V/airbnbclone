package com.owuor.airbnbclone.auth.repository;

import com.owuor.airbnbclone.auth.entity.TrackAdminLogin;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface TrackAdminLoginRepository extends JpaRepository<TrackAdminLogin, Long> {
    @Query("SELECT t.userId, COUNT(t) " +
            "FROM TrackAdminLogin t " +
            "WHERE t.loginTime BETWEEN :startDate AND :endDate " +
            "GROUP BY t.userId")
    List<Object[]> findLoginsByDateRangeRaw(@Param("startDate") LocalDateTime startDate,
                                            @Param("endDate") LocalDateTime endDate);
}
