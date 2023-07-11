package io.samtech.security.data.models.token;

import io.samtech.security.data.models.user.User;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.Calendar;
import java.util.Date;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Entity
public class VerificationToken {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    @Column(unique = true)
    private String token;
    @OneToOne(targetEntity = User.class, fetch = FetchType.EAGER)
    @JoinColumn(name = "user_id")
    private User user;
    private final LocalDateTime createdAt = LocalDateTime.now();
    private final LocalDateTime expirationTime = createdAt.plusMinutes(10L);

    public VerificationToken(User user, String token){
        super();
        this.user = user;
        this.token = token;
    }


}
