package com.datweb.spring.security.register_login_jwt.Service.Impl;

import com.datweb.spring.security.register_login_jwt.Dto.AccountLoginDto;
import com.datweb.spring.security.register_login_jwt.Dto.AccountRegisterDto;
import com.datweb.spring.security.register_login_jwt.Entity.Token;
import com.datweb.spring.security.register_login_jwt.Entity.Role;
import com.datweb.spring.security.register_login_jwt.Entity.User;
import com.datweb.spring.security.register_login_jwt.Repository.TokenRepository;
import com.datweb.spring.security.register_login_jwt.Repository.UserRepository;
import com.datweb.spring.security.register_login_jwt.Service.AuthenticationService;
import com.datweb.spring.security.register_login_jwt.Service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import java.util.Date;


@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {
    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;

    public UserDetails register(AccountRegisterDto accountRegisterDto){
        User user = new User();
        user.setRole(Role.USER);
        user.setPassword(passwordEncoder.encode(accountRegisterDto.getPassword()));
        user.setEmail(accountRegisterDto.getEmail());
        user.setFirstname(accountRegisterDto.getFirstname());
        user.setLastname(accountRegisterDto.getLastname());
        userRepository.save(user);
        return user;
    }

    public Token login(AccountLoginDto accountLoginDto){
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(accountLoginDto.getEmail(), accountLoginDto.getPassword()));
        User user = userRepository.findByEmail(accountLoginDto.getEmail()).get();
        if (user != null) {
            String token = jwtService.generateToken(user);
            Token tokenDto = new Token();
            tokenDto.setToken(token);
            tokenDto.setExpirationTime(new Date(System.currentTimeMillis()+15*60*1000));
            tokenRepository.save(tokenDto);
            return tokenDto;
        }
        return null;
    }
}
