package com.datweb.spring.security.register_login_jwt.Service;

import com.datweb.spring.security.register_login_jwt.Dto.AccountForgotPassword;
import com.datweb.spring.security.register_login_jwt.Dto.PasswordDto;
import com.datweb.spring.security.register_login_jwt.Entity.Token;
import com.datweb.spring.security.register_login_jwt.Entity.User;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface UserService {
    UserDetailsService userDetailsService();
    void saveTokenForUser(User user, String token);

    String applicationUrl(HttpServletRequest request);

    boolean checkVerifyToken(String token);

    Token generateResendToken(String oldToken);

    void resendVerifyLink(String newToken, String applicationUrl);

    void changeStatus(String token);

    boolean checkAccount(AccountForgotPassword accountForgotPassword);

    void sendLinkResetPassword(AccountForgotPassword accountForgotPassword, String url);

    String savePassword(String token, PasswordDto passwordDto);
}
