package com.datweb.spring.security.register_login_jwt.Service;

import com.datweb.spring.security.register_login_jwt.Dto.AccountDto;
import com.datweb.spring.security.register_login_jwt.Dto.AccountRegisterDto;
import com.datweb.spring.security.register_login_jwt.Entity.VerifyToken;
import org.springframework.security.core.userdetails.UserDetails;

public interface AuthenticationService {
    UserDetails register(AccountRegisterDto accountRegisterDto);
    VerifyToken login(AccountDto accountDto);
}
