package com.owuor.airbnbclone.common.responses;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class GenerateTokenResponse {
    private String token;
    private LocalDateTime expiresOn;
    private String jti;
    private String deviceInfo;

}
