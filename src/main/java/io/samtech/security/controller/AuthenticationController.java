package io.samtech.security.controller;

import io.samtech.security.data.dto.request.AuthenticationRequest;
import io.samtech.security.data.dto.request.VerifyRequest;
import io.samtech.security.data.dto.response.ApiResponse;
import io.samtech.security.data.dto.response.AuthenticationResponse;
import io.samtech.security.data.dto.request.RegisterRequest;
import io.samtech.security.data.models.token.VerificationToken;
import io.samtech.security.data.models.user.User;
import io.samtech.security.data.repository.VerificationRepository;
import io.samtech.security.exception.BusinessLogicException;
import io.samtech.security.exception.UserAlreadyExistException;
import io.samtech.security.exception.UserNotFoundException;
import io.samtech.security.notification.event.RegistrationCompleteEvent;
import io.samtech.security.service.AuthenticationService;
import io.samtech.security.service.IVerificationTokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.Optional;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService service;
    private final IVerificationTokenService verificationTokenService;
    private final ApplicationEventPublisher publisher;
    private final VerificationRepository verificationRepository;

    @PostMapping("/register")
    public ResponseEntity<ApiResponse> register(@RequestBody RegisterRequest request) throws UserAlreadyExistException {
        return ResponseEntity.ok(service.register(request));
    }

//    @PostMapping("/signup")
//    public ResponseEntity<String> signup(@RequestBody RegisterRequest registerRequest, final  HttpServletRequest request) throws UserAlreadyExistException {
//        User user = service.signup(registerRequest);
//        publisher.publishEvent(new RegistrationCompleteEvent(user, applicationUrl(request)));
//        return ResponseEntity.ok( "Success! Please check your email to complete your registration");
//    }

//    private String applicationUrl(HttpServletRequest request) {
//        return "http://"+request.getServerName()+":"+request.getServerPort()+request.getContextPath();
//    }
//    @GetMapping("/verify-email")
//    public ResponseEntity<String> verifyEmail(@RequestParam("token") String token){
//        Optional<VerificationToken> verifyToken = verificationRepository.findByToken(token);
//        if (verifyTokenisEnabled()){
//            return ResponseEntity.ok("This account has already been verified, please login.");
//        }
//        String verificationResult = String.valueOf(verificationTokenService.validateToken(token));
//        if (verificationResult.equalsIgnoreCase("valid token")){
//            return ResponseEntity.ok("Email verified successfully. Now you can login to your account");
//        }
//        return ResponseEntity.ok("Invalid verification token");
//    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request){
        return ResponseEntity.ok(service.authenticate(request));
    }

    @PostMapping("/refresh-token")
    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
       service.refreshToken(request, response);
    }

    @PostMapping("/account/verify")
    public ResponseEntity<ApiResponse>verifyAccount(@RequestBody VerifyRequest verifyRequest) {
        try {
            var response = service.verifyAccount(verifyRequest);
            return ResponseEntity.ok(response);
        } catch (UserNotFoundException exception) {
            return ResponseEntity.badRequest().body(
                    ApiResponse.builder()
                            .message(exception.getMessage())
                            .build()
            );

        }
    }
}
