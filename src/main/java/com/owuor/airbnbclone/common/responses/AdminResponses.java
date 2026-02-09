package com.owuor.airbnbclone.common.responses;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AdminResponses {

    private String userId;
    private String adminName;
    private String email;
    private String employeeId;
    private String phoneNumber;

}
