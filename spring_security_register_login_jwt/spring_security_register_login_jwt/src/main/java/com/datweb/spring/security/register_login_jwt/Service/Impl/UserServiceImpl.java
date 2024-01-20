package com.datweb.spring.security.register_login_jwt.Service.Impl;

import com.datweb.spring.security.register_login_jwt.Dto.AccountDto;
import com.datweb.spring.security.register_login_jwt.Dto.AccountForgotPassword;
import com.datweb.spring.security.register_login_jwt.Dto.PasswordDto;
import com.datweb.spring.security.register_login_jwt.Entity.ResetToken;
import com.datweb.spring.security.register_login_jwt.Entity.VerifyToken;
import com.datweb.spring.security.register_login_jwt.Entity.User;
import com.datweb.spring.security.register_login_jwt.Repository.ResetTokenRepository;
import com.datweb.spring.security.register_login_jwt.Repository.VerifyTokenRepository;
import com.datweb.spring.security.register_login_jwt.Repository.UserRepository;
import com.datweb.spring.security.register_login_jwt.Service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final VerifyTokenRepository verifyTokenRepository;
    private final ResetTokenRepository resetTokenRepository;
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
        VerifyToken saveVerifyToken = new VerifyToken(user, token);
        verifyTokenRepository.save(saveVerifyToken);
    }

    @Override
    public String applicationUrl(HttpServletRequest request) {
        return "http://"+request.getServerName()+":"+request.getServerPort()+request.getContextPath();
    }

    @Override
    public boolean checkVerifyToken(String token){
        Optional<VerifyToken> tokenOptional = verifyTokenRepository.findByToken(token);
        if (tokenOptional.isPresent()){
            VerifyToken _Verify_token = tokenOptional.get();
            if(_Verify_token.getExpirationTime().before(new Date())){
                return false;
            }
            return true;
        }
        return false;
    }

    @Override
    public VerifyToken generateResendToken(String oldToken) {
        VerifyToken verifyToken = verifyTokenRepository.findByToken(oldToken).get();
        verifyToken.setToken(UUID.randomUUID().toString());
        verifyToken.setExpirationTime(new Date(System.currentTimeMillis()+15*60*1000));
        verifyTokenRepository.save(verifyToken);
        return verifyToken;
    }

    @Override
    public void resendVerifyLink(String token,String applicationUrl){
        String url = applicationUrl+"/auth/verify?token="+token;
        log.info("Click the link to verify your account : {}", url);
    }

    @Override
    public void changeStatus(String token){
        VerifyToken _Verify_token = verifyTokenRepository.findByToken(token).get();
        User user = _Verify_token.getUser();
        user.setEnable(true);
        userRepository.save(user);
    }

    @Override
    public boolean checkAccount(AccountForgotPassword accountForgotPassword) {
        User user = userRepository.findByEmail(accountForgotPassword.getEmail()).get();
        if (user != null && user.isEnabled()) return true;
        return false;
    }

    @Override
    public void sendLinkResetPassword(AccountForgotPassword accountForgotPassword, String url) {
        User user = userRepository.findByEmail(accountForgotPassword.getEmail()).get();
        String token = UUID.randomUUID().toString();
        ResetToken resetToken = new ResetToken(user,token);
        resetTokenRepository.save(resetToken);
        String _url = url + "/auth/savePassword?token=" + resetToken.getToken();
        log.info("Click the link to reset password: {}", _url);
    }

    @Override
    public String savePassword(String token, PasswordDto passwordDto) {
        ResetToken resetToken = resetTokenRepository.findByToken(token);
        if(resetToken != null){
            User user = resetToken.getUser();
            user.setPassword(new BCryptPasswordEncoder().encode(passwordDto.getNewPassword()));
            userRepository.save(user);
            resetTokenRepository.delete(resetToken);
            return "success";
        }
        return "invalid token";
    }

    @Override
    public boolean checkOldPassword(String email, String oldPassword) {
        User user = userRepository.getUserByEmailAndPassword(email, new BCryptPasswordEncoder().encode(oldPassword));
        if(user != null){
            return true;
        }
        return false;
    }

    @Override
    public void changePassword(String email, String newPassword) {
        User user = userRepository.findByEmail(email).get();
        user.setPassword(new BCryptPasswordEncoder().encode(newPassword));
        userRepository.save(user);
    }

    @Override
    public void sendLinkChangePassword(AccountDto accountDto, String url) {
        User user = userRepository.findByEmail(accountDto.getEmail()).get();
        String token = UUID.randomUUID().toString();
        ResetToken resetToken = new ResetToken(user, token);
        resetTokenRepository.save(resetToken);
        String _url = url + "/auth/savePassword?token=" + resetToken.getToken();
        log.info("Click the link to reset password: {}", _url);
    }
}
