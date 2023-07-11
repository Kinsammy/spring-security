package io.samtech.security.service;

import io.samtech.security.data.models.token.VerificationToken;
import io.samtech.security.data.models.user.User;
import io.samtech.security.data.repository.UserRepository;
import io.samtech.security.data.repository.VerificationRepository;
import io.samtech.security.utils.AppUtilities;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class VerificationTokenService implements IVerificationTokenService{
    private final VerificationRepository verificationRepository;
    private final UserRepository userRepository;
    @Override
    public String generateAndSaveToken(User user) {
        Optional<VerificationToken> existingToken = verificationRepository.findVerificationTokenByUser(user);
        existingToken.ifPresent(verificationRepository::delete);
        String generateToken = AppUtilities.generaterRandomString(64);
        VerificationToken myToken = VerificationToken.builder()
                .user(user)
                .token(generateToken)
                .build();
        verificationRepository.save(myToken);
        return generateToken;
    }

    @Override
    public Optional<VerificationToken> validateReceiveToken(User user, String token) {
        Optional<VerificationToken> receivedToken = verificationRepository.findVerificationTokenByUserAndToken(user, token);
        if (receivedToken.isEmpty()) throw new RuntimeException("Invalid token");
        else if (receivedToken.get().getExpirationTime().isBefore(LocalDateTime.now())){
            verificationRepository.delete(receivedToken.get());
            throw new RuntimeException("Token is expired");
        }
        return receivedToken;
    }

    @Override
    public Optional<VerificationToken> validateToken(String token) {
        Optional<VerificationToken> verifyToken = verificationRepository.findByToken(token);
        if (verifyToken == null){
            throw new RuntimeException("Invalid verification token");
        }
        else if (verifyToken.get().getExpirationTime().isBefore(LocalDateTime.now())){
            verificationRepository.delete(verifyToken.get());
            throw new RuntimeException("verification token already expired");
        }

        return verifyToken;
    }

    @Override
    public void deleteToken(VerificationToken token) {
        verificationRepository.delete(token);
    }

    @Override
    public void saveUserVerificationToken(User user, String token) {
        var verificationToken = new VerificationToken(user, token);
        verificationRepository.save(verificationToken);
    }
}
