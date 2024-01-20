package com.datweb.spring.security.register_login_jwt.Entity;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Data
@Entity
@NoArgsConstructor
@Table(name = "verify_token")
public class VerifyToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String token;
    private Date expirationTime;
    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "user_id")
    private User user;

    public VerifyToken(User user, String token) {
        super();
        this.user = user;
        this.token = token;
        this.expirationTime = new Date(System.currentTimeMillis()+15*60*1000);
    }
}
