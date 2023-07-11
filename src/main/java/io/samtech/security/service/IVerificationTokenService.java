package io.samtech.security.service;

import io.samtech.security.data.models.token.VerificationToken;
import io.samtech.security.data.models.user.User;

import java.util.Optional;

public interface IVerificationTokenService {
    String generateAndSaveToken(User user);
    Optional<VerificationToken> validateReceiveToken(User user, String token);
    Optional<VerificationToken> validateToken(String token);
    void deleteToken(VerificationToken token);

    void saveUserVerificationToken(User user, String token);
}
