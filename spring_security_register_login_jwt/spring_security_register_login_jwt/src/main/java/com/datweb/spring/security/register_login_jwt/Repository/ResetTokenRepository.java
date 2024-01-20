package com.datweb.spring.security.register_login_jwt.Repository;

import com.datweb.spring.security.register_login_jwt.Entity.ResetToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ResetTokenRepository extends JpaRepository<ResetToken, Long> {
    ResetToken findByToken(String token);
}
