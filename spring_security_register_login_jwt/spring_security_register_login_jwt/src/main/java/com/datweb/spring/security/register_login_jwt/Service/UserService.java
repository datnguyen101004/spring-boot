package com.datweb.spring.security.register_login_jwt.Service;

import com.datweb.spring.security.register_login_jwt.Dto.AccountDto;
import com.datweb.spring.security.register_login_jwt.Dto.AccountForgotPassword;
import com.datweb.spring.security.register_login_jwt.Dto.PasswordDto;
import com.datweb.spring.security.register_login_jwt.Entity.VerifyToken;
import com.datweb.spring.security.register_login_jwt.Entity.User;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface UserService {
    UserDetailsService userDetailsService();
    void saveTokenForUser(User user, String token);

    String applicationUrl(HttpServletRequest request);

    boolean checkVerifyToken(String token);

    VerifyToken generateResendToken(String oldToken);

    void resendVerifyLink(String newToken, String applicationUrl);

    void changeStatus(String token);

    boolean checkAccount(AccountForgotPassword accountForgotPassword);

    void sendLinkResetPassword(AccountForgotPassword accountForgotPassword, String url);

    String savePassword(String token, PasswordDto passwordDto);

    boolean checkOldPassword(String email, String oldPassword);

    void changePassword(String email, String newPassword);

    void sendLinkChangePassword(AccountDto accountDto, String url);
}
