package com.santechture.api.dto.admin;

import com.santechture.api.entity.Admin;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.persistence.Basic;
import javax.persistence.Column;
import java.util.ArrayList;
import java.util.Collection;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class AdminDto {

    private Integer adminId;

    private String username;
    private String accessToken;

    public AdminDto(Admin admin) {
        setAdminId(admin.getAdminId());
        setUsername(admin.getUsername());
        setAccessToken(admin.getAccessToken());
    }

}