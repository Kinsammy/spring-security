package io.samtech.security.data.models.token;

import io.samtech.security.data.models.user.User;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class Token {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long Id;
    private String token;
    @Enumerated(EnumType.STRING)
    private TokenType tokenType;
    private boolean expired;
    private boolean revoked;
    private final LocalDateTime createdAt = LocalDateTime.now();
    private final LocalDateTime expiryTime = createdAt.plusMinutes(5);

    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;

}
