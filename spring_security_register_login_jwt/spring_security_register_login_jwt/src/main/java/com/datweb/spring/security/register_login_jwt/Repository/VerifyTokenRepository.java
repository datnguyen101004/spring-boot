package com.datweb.spring.security.register_login_jwt.Repository;

import com.datweb.spring.security.register_login_jwt.Entity.VerifyToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface VerifyTokenRepository extends JpaRepository<VerifyToken, Long> {
    Optional<VerifyToken> findByToken(String token);
}
