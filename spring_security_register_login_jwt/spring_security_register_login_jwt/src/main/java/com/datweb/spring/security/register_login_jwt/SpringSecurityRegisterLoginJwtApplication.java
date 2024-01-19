package com.datweb.spring.security.register_login_jwt;

import com.datweb.spring.security.register_login_jwt.Entity.Role;
import com.datweb.spring.security.register_login_jwt.Entity.User;
import com.datweb.spring.security.register_login_jwt.Repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Optional;

@SpringBootApplication
@RequiredArgsConstructor
public class SpringSecurityRegisterLoginJwtApplication implements CommandLineRunner {
	private final UserRepository userRepository;

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityRegisterLoginJwtApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {
		Optional<User> user = userRepository.findByRole(Role.ADMIN);
		if(user.isEmpty()){
			User adminUser = new User();
			adminUser.setPassword(new BCryptPasswordEncoder().encode("admin"));
			adminUser.setEmail("admin@gmail.com");
			adminUser.setEnable(true);
			adminUser.setRole(Role.ADMIN);
			userRepository.save(adminUser);
		}
	}
}
