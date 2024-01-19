package com.datweb.spring.security.register_login_jwt.Service;

import org.springframework.security.core.userdetails.UserDetails;

public interface JwtService {
    String generateToken(UserDetails user);
    String extractUsername(String token);
    Boolean isTokenValid(String token, UserDetails userDetails);
}
