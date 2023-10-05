package com.santechture.api.service;

import com.santechture.api.configuration.JwtService;
import com.santechture.api.dto.GeneralResponse;
import com.santechture.api.dto.admin.AdminDto;
import com.santechture.api.entity.Admin;
import com.santechture.api.exception.BusinessExceptions;
import com.santechture.api.repository.AdminRepository;
import com.santechture.api.validation.LoginRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import static com.santechture.api.configuration.JwtService.TOKENS_MAP;

@Service
public class AdminService {


    private final AdminRepository adminRepository;
    private final AuthenticationManager authenticationManager;

    private final JwtService jwtService;

    public AdminService(AdminRepository adminRepository, AuthenticationManager authenticationManager, JwtService jwtService) {
        this.adminRepository = adminRepository;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
    }

    public ResponseEntity<GeneralResponse> login(LoginRequest request) throws BusinessExceptions {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getUsername(), request.getPassword())
            );
            Admin admin = (Admin) authentication.getPrincipal();
            String accessToken = jwtService.generateToken(admin);
            TOKENS_MAP.put(String.format("%s,%s", admin.getAdminId(), admin.getUsername()),accessToken);
            admin.setAccessToken(accessToken);
            System.out.println("admin.getAccessToken---> "+admin.getAccessToken());
            return new GeneralResponse().response(new AdminDto(admin));
        } catch (BadCredentialsException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

    }

}
