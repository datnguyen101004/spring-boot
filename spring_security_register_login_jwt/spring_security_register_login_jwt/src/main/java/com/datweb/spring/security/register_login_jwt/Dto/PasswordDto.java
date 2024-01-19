package com.datweb.spring.security.register_login_jwt.Dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class PasswordDto {
    private String oldPassword;
    private String newPassword;
}
