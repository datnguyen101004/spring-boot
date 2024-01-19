package com.datweb.spring.security.register_login_jwt.Repository;

import com.datweb.spring.security.register_login_jwt.Entity.Token;
import com.datweb.spring.security.register_login_jwt.Entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface TokenRepository extends JpaRepository<Token, Long> {
    Optional<Token> findByToken(String token);
}
