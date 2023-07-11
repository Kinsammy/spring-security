package io.samtech.security.data.repository;

import io.samtech.security.data.models.token.VerificationToken;
import io.samtech.security.data.models.user.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface VerificationRepository  extends JpaRepository<VerificationToken, Long> {
    Optional<VerificationToken> findVerificationTokenByUserAndToken(User user, String token);

    Optional<VerificationToken> findVerificationTokenByUser(User user);

    Optional<VerificationToken> findByToken(String token);
}
