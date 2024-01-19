package com.datweb.spring.security.register_login_jwt.Dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AccountRegisterDto {
    private String email;
    private String password;
    private String firstname;
    private String lastname;
}
