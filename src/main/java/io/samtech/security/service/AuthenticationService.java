package io.samtech.security.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.fge.jsonpatch.JsonPatch;
import io.samtech.security.config.security.service.JwtService;
import io.samtech.security.data.dto.request.*;
import io.samtech.security.data.dto.response.ApiResponse;
import io.samtech.security.data.dto.response.AuthenticationResponse;
import io.samtech.security.data.dto.response.UploadResponse;
import io.samtech.security.data.models.token.Token;
import io.samtech.security.data.models.token.TokenType;
import io.samtech.security.data.models.token.VerificationToken;
import io.samtech.security.data.models.user.User;
import io.samtech.security.data.repository.TokenRepository;
import io.samtech.security.data.repository.UserRepository;
import io.samtech.security.data.repository.VerificationRepository;
import io.samtech.security.exception.*;
import io.samtech.security.notification.MailService;
import io.samtech.security.service.serviceInterface.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Optional;


@Service
@RequiredArgsConstructor
public class AuthenticationService implements UserService {
    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final VerificationRepository verificationRepository;
    private final PasswordEncoder passwordEncoder;
    private final IVerificationTokenService iVerificationTokenService;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final MailService mailService;

    public ApiResponse register(RegisterRequest request) throws UserAlreadyExistException {
        if (emailExists(request.getEmail())) {
            throw new UserAlreadyExistException("There is an account with that email address: " + request.getEmail());
        }

        var user = User.builder()
                .name(request.getName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole())
                .build();
        var savedUser = userRepository.save(user);
        String token = iVerificationTokenService.generateAndSaveToken(savedUser);

        buildNotificationRequest(savedUser, token);


//
        return ApiResponse.builder()
                .message("Registration Successful")
                .build();
    }

    public AuthenticationResponse registerAdminAndManager(RegisterRequest request){
        var user = User.builder()
                .name(request.getName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole())
                .build();
        var savedUser = userRepository.save(user);
        var jwtToken = jwtService.generateToken(user);
        revokeAllUserTokens(user);
        saveUserToken(savedUser, jwtToken);
        var refreshToken = jwtService.generateRefreshToken(user);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }





    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        var jwtToken = jwtService.generateToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user, jwtToken);
        var refreshToken = jwtService.generateRefreshToken(user);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    private void revokeAllUserTokens(User user){
        var validUserTokens = tokenRepository.findAllValidTokensByUserId(user.getId());
        if (validUserTokens.isEmpty()){
            return;
        }
        validUserTokens.forEach(t -> {
            t.setExpired(true);
            t.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);

    }

    private void saveUserToken(User user, String jwtToken) {
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .revoked(false)
                .expired(false)
                .build();
        tokenRepository.save(token);
    }

    public void refreshToken(HttpServletRequest request,
                             HttpServletResponse response
    ) throws IOException {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
        final String userEmail;
        if (authHeader == null ||!authHeader.startsWith("Bearer ")){
            return;
        }
        refreshToken = authHeader.substring(7);
        userEmail = jwtService.extractUsername(refreshToken);
        if (userEmail !=null){
            var user= this.userRepository.findByEmail(userEmail).orElseThrow();
            if (jwtService.isTokenValid(refreshToken, user)) {
                    //  Generate access token, but the refresh token will still remain
                var accessToken = jwtService.generateToken(user);
                revokeAllUserTokens(user);
                saveUserToken(user, accessToken);
                var authResponse = AuthenticationResponse.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .build();
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            }
        }
    }


    @Override
    public User getUserByEmail(String email) throws LogicException {
        return userRepository.findByEmail(email).orElseThrow(
                ()-> new LogicException(String.format("Email " + email + " not found")));
    }

    private boolean emailExists(String email){
        return userRepository.findByEmail(email).isPresent();
    }

    @Override
    public User getUserById(Long userId) throws UserNotFoundException {
        return userRepository.findById(userId).orElseThrow(
                ()-> new UserNotFoundException("User not found")
        );
    }

    @Override
    public ApiResponse verifyAccount(VerifyRequest verifyRequest) throws RegistrationException, UserNotFoundException {
        if (getUserByEmail(verifyRequest.getEmail()) == null) throw new UserNotFoundException("Invalid email");
        User user = getUserByEmail(verifyRequest.getEmail());
        Optional<VerificationToken> receivedToken = iVerificationTokenService.validateReceiveToken(user, verifyRequest.getVerificationToken());
        user.setEnabled(true);
        userRepository.save(user);
        iVerificationTokenService.deleteToken(receivedToken.get());
        return ApiResponse.builder()
                .message("Verification Successful")
                .build();

    }

    @Override
    public void sendResetPasswordMail(String email) throws LogicException {

    }

    @Override
    public AuthenticationResponse updateUser(Long userId, JsonPatch updatePayLoad) {
        return null;
    }

    @Override
    public void updateUser(User user) {
        userRepository.save(user);
    }

    @Override
    public UploadResponse uploadProfileImage(MultipartFile profileImage, Long userId) throws ImageUploadException {
        return null;
    }

    @Override
    public void resetPassword(String email, String otp, String newPassword) throws RegistrationException, LogicException {

    }

    @Override
    public void changePassword(String email, String otp, String newPassword) throws RegistrationException, LogicException {

    }

    @Override
    public void sendVerifyLink(@NotNull User user) {

    }

    @Override
    public void sendVerifyOtp(User user) {

    }




    private void buildNotificationRequest(User user, String token){
        EmailNotificationRequest request = new EmailNotificationRequest();      
        request.getTo().add(new Recipient(user.getName(), user.getEmail()));
        request.setHtmlContent("To activate your Account enter the following digits on your web browser\n\n" + token);
        mailService.sendHtmlMail(request);
    }


//    public User signup(RegisterRequest registerRequest) throws UserAlreadyExistException {
//        Optional<User> user = userRepository.findByEmail(registerRequest.getEmail());
//        if (user.isPresent()) throw new UserAlreadyExistException(
//                String.format("User with email %s already exists", registerRequest.getEmail())
//        );
//        var newUser = new User();
//        newUser.setName(registerRequest.getName());
//        newUser.setEmail(registerRequest.getEmail());
//        newUser.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
//        newUser.setRole(registerRequest.getRole());
//        return userRepository.save(newUser);
//    }
}
