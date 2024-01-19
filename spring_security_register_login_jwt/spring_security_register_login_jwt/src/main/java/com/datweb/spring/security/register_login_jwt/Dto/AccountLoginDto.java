package com.datweb.spring.security.register_login_jwt.Dto;

import lombok.Data;

@Data
public class AccountLoginDto {
    private String email;
    private String password;
}
