package com.datweb.spring.security.register_login_jwt.Event;
import com.datweb.spring.security.register_login_jwt.Entity.User;
import com.datweb.spring.security.register_login_jwt.Service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Component;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class RegisterEventListener implements ApplicationListener<RegisterEvent> {
    private final UserService userService;
    @Override
    public void onApplicationEvent(RegisterEvent event) {
        //Create a verified random token
        User user = event.getUser();
        String token = UUID.randomUUID().toString();
        userService.saveTokenForUser(user, token);
        //Send link to email
        String url = event.getUrl()+"/auth/verify?token="+token;
        //Send verification link email
        log.info("Click the link to verify your email : {}",url);
    }
}
