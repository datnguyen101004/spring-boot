package com.datweb.spring.security.register_login_jwt.Repository;

import com.datweb.spring.security.register_login_jwt.Entity.Role;
import com.datweb.spring.security.register_login_jwt.Entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);
    Optional<User> findByRole(Role role);
}
