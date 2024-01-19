package com.datweb.spring.security.register_login_jwt.Event;

import com.datweb.spring.security.register_login_jwt.Entity.User;
import lombok.Getter;
import lombok.Setter;
import org.springframework.context.ApplicationEvent;

@Getter
@Setter
public class RegisterEvent extends ApplicationEvent {
    private User user;
    private String url;
    public RegisterEvent(User user, String url) {
        super(user);
        this.user = user;
        this.url = url;
    }
}
