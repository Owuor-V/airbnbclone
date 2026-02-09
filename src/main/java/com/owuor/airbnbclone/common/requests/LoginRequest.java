package com.owuor.airbnbclone.common.requests;

import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data
@Builder
public class LoginRequest {

    @NotEmpty(message = "Invalid User Id")
    private String userId;
    @NotEmpty(message = "Invalid User Id")
    private String password;
}
