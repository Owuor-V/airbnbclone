package com.owuor.airbnbclone.auth.service;

import com.owuor.airbnbclone.auth.entity.AdminEntity;
import com.owuor.airbnbclone.auth.repository.AdminRepository;
import com.owuor.airbnbclone.common.requests.AdminRequest;
import com.owuor.airbnbclone.common.responses.AdminResponses;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
@NoArgsConstructor

public class AdminService {

    @Autowired
    private AdminRepository adminRepository;

    public AdminResponses createAdmin(AdminRequest adminRequest) {

        if (adminRepository.existsByUserId(adminRequest.getUserId())) {
            throw new IllegalArgumentException("User Id already exists");
        }

        if (adminRepository.existsByEmployeeId(adminRequest.getEmployeeId())) {
            throw new IllegalArgumentException("Employee Id already exists");
        }

        AdminEntity adminEntity = new AdminEntity();
        adminEntity.setUserId(adminRequest.getUserId());
        adminEntity.setAdminName(adminRequest.getAdminName());
        adminEntity.setEmail(adminRequest.getEmail());
        adminEntity.setEmployeeId(adminRequest.getEmployeeId());
        adminEntity.setPhoneNumber(adminRequest.getPhoneNumber());

        AdminEntity savedAdmin = adminRepository.save(adminEntity);

        AdminResponses response = new AdminResponses();
        response.setUserId(savedAdmin.getUserId());
        response.setAdminName(savedAdmin.getAdminName());
        response.setEmail(savedAdmin.getEmail());
        response.setEmployeeId(savedAdmin.getEmployeeId());
        response.setPhoneNumber(savedAdmin.getPhoneNumber());

        return response;
    }

}
