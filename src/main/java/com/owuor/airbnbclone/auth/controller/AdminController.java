package com.owuor.airbnbclone.auth.controller;

import com.owuor.airbnbclone.auth.service.AdminService;
import com.owuor.airbnbclone.common.requests.AdminRequest;
import com.owuor.airbnbclone.common.requests.LoginRequest;
import com.owuor.airbnbclone.common.responses.AdminResponses;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import javax.security.auth.login.AccountLockedException;
import java.io.IOException;

public class AdminController {

    private AdminService adminService;

    @PostMapping("/admin/login")
    public ResponseEntity<AdminResponses> login(@RequestBody @Valid LoginRequest loginRequest, HttpServletResponse servletResponse, HttpServletRequest servletRequest) throws AccountLockedException, IOException {
        return new ResponseEntity<>(adminService.login(loginRequest,servletResponse,servletRequest), HttpStatus.OK);
    }

    @PostMapping("/admin/creat")
    public ResponseEntity<AdminResponses> createAdmin (@RequestBody AdminRequest adminRequest) {
        return new ResponseEntity<>(adminService.createAdmin(adminRequest).getStatusCode());
    }
}
