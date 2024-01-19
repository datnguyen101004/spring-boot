package com.datweb.spring.security.register_login_jwt.Service.Impl;

import com.datweb.spring.security.register_login_jwt.Dto.AccountForgotPassword;
import com.datweb.spring.security.register_login_jwt.Dto.PasswordDto;
import com.datweb.spring.security.register_login_jwt.Entity.Token;
import com.datweb.spring.security.register_login_jwt.Entity.User;
import com.datweb.spring.security.register_login_jwt.Repository.TokenRepository;
import com.datweb.spring.security.register_login_jwt.Repository.UserRepository;
import com.datweb.spring.security.register_login_jwt.Service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    public UserDetailsService userDetailsService(){
        return new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
                return userRepository.findByEmail(email).get();
            }
        };
    }

    @Override
    public void saveTokenForUser(User user, String token){
        Token saveToken = new Token(user, token);
        tokenRepository.save(saveToken);
    }

    @Override
    public String applicationUrl(HttpServletRequest request) {
        return "http://"+request.getServerName()+":"+request.getServerPort()+request.getContextPath();
    }

    @Override
    public boolean checkVerifyToken(String token){
        Optional<Token> tokenOptional = tokenRepository.findByToken(token);
        if (tokenOptional.isPresent()){
            Token _token = tokenOptional.get();
            if(_token.getExpirationTime().before(new Date())){
                return false;
            }
            return true;
        }
        return false;
    }

    @Override
    public Token generateResendToken(String oldToken) {
        Token token = tokenRepository.findByToken(oldToken).get();
        token.setToken(UUID.randomUUID().toString());
        token.setExpirationTime(new Date(System.currentTimeMillis()+15*60*1000));
        tokenRepository.save(token);
        return token;
    }

    @Override
    public void resendVerifyLink(String token,String applicationUrl){
        String url = applicationUrl+"/auth/verify?token="+token;
        log.info("Click the link to verify your account : {}", url);
    }

    @Override
    public void changeStatus(String token){
        Token _token = tokenRepository.findByToken(token).get();
        User user = _token.getUser();
        user.setEnable(true);
        userRepository.save(user);
    }

    @Override
    public boolean checkAccount(AccountForgotPassword accountForgotPassword) {
        User user = userRepository.findByEmail(accountForgotPassword.getEmail()).get();
        if (user != null) return true;
        return false;
    }

    @Override
    public void sendLinkResetPassword(AccountForgotPassword accountForgotPassword, String url) {
        User user = userRepository.findByEmail(accountForgotPassword.getEmail()).get();
        Token _token = user.getToken();
        _token.setToken(UUID.randomUUID().toString());
        tokenRepository.save(_token);
        String _url = url + "/auth/savePassword?token=" + _token.getToken();
        log.info("Click the link to reset password: {}", _url);
    }

    @Override
    public String savePassword(String token, PasswordDto passwordDto) {
        Token _token = tokenRepository.findByToken(token).get();
        if(_token != null){
            User user = _token.getUser();
            user.setPassword(new BCryptPasswordEncoder(Integer.parseInt(passwordDto.getNewPassword())).toString());
            userRepository.save(user);
            return "success";
        }
        return "invalid token";
    }
}
