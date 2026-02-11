package com.owuor.airbnbclone.common.config.entity;

import com.owuor.airbnbclone.enumlist.SessionFlag;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Entity

public class SessionTimeMgt {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;
    private Integer accessTokenExpiryTime;
    private Integer refreshTokenExpiryTime;
    @Enumerated(EnumType.STRING)
    private SessionFlag sessionFlag;
}
