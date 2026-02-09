package com.owuor.airbnbclone.common.requests;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class AdminRequest {

//    @NotNull(message = "Role Id cannot be null")
//    private Long roleId;

    @NotBlank(message = "User Id cannot be blank")
    private String userId;

    @NotBlank(message = "Admin name cannot be blank")
    private String adminName;

    @NotBlank(message = "Email cannot be blank")
    @Email(message = "Invalid email")
    private String email;

    @NotBlank(message = "Employee Id cannot be null")
    private String employeeId;

    @NotBlank(message = "Phone number cannot be blank")
    @Pattern(regexp = "^\\d{10}$", message = "Phone number must be 10 digits")
    private String phoneNumber;

}
