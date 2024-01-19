package com.datweb.spring.security.register_login_jwt.Controller;
import com.datweb.spring.security.register_login_jwt.Dto.AccountForgotPassword;
import com.datweb.spring.security.register_login_jwt.Dto.PasswordDto;
import com.datweb.spring.security.register_login_jwt.Entity.User;
import com.datweb.spring.security.register_login_jwt.Event.RegisterEvent;
import com.datweb.spring.security.register_login_jwt.Dto.AccountLoginDto;
import com.datweb.spring.security.register_login_jwt.Dto.AccountRegisterDto;
import com.datweb.spring.security.register_login_jwt.Entity.Token;
import com.datweb.spring.security.register_login_jwt.Service.AuthenticationService;
import com.datweb.spring.security.register_login_jwt.Service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final UserService userService;
    private final AuthenticationService authenticationService;
    private final ApplicationEventPublisher applicationEventPublisher;
    @PostMapping("/register")
    public ResponseEntity<UserDetails> register(@RequestBody AccountRegisterDto accountRegisterDto, final HttpServletRequest request){
        User user = (User) authenticationService.register(accountRegisterDto);
        applicationEventPublisher.publishEvent(new RegisterEvent(
                user, userService.applicationUrl(request)
        ));
        return ResponseEntity.ok(user);
    }

    @PostMapping("/login")
    public ResponseEntity<Token> login(@RequestBody AccountLoginDto accountLoginDto){
        return ResponseEntity.ok(authenticationService.login(accountLoginDto));
    }

    @GetMapping("/verify")
    public String verifyPage(@RequestParam("token") String token){
        if(userService.checkVerifyToken(token)) {
            userService.changeStatus(token);
            return "Your account is enabled";
        }
        return "invalid token";
    }

    @GetMapping("/resend/verify")
    public String resendVerifyPage(@RequestParam("token") String oldToken,
                                   HttpServletRequest request){
        Token newToken = userService.generateResendToken(oldToken);
        userService.resendVerifyLink(newToken.getToken(), userService.applicationUrl(request));
        return "Verify link is sent";
    }

    @PostMapping("/resetPassword")
    public String resetPassword(@RequestBody AccountForgotPassword accountForgotPassword,
                                HttpServletRequest request){
        if(userService.checkAccount(accountForgotPassword)){
            userService.sendLinkResetPassword(accountForgotPassword, userService.applicationUrl(request));
            return "Link reset password is sent";
        }
        return "Invalid email";
    }

    @PostMapping("/savePassword")
    public String savePassword(@RequestParam("token") String token,
                               @RequestBody PasswordDto passwordDto){
        if(userService.savePassword(token, passwordDto).equals("success")){
            return "success";
        }
        return "invalid token";
    }
}
