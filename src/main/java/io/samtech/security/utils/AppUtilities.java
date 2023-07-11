package io.samtech.security.utils;

import io.samtech.security.config.security.service.JwtService;
import io.samtech.security.exception.BusinessLogicException;
import jakarta.validation.constraints.NotNull;
import org.springframework.beans.factory.annotation.Value;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.stream.Collectors;

public class AppUtilities {
    @Value("${application.security.jwt.secret-key}")
    private static String jwtSecretKey;
    private static JwtService jwtService;
    public static final int NUMBER_OF_ITEMS_PER_PAGE = 3;
    private static  final String USER_VERIFICATION_BASE_URL= "/home/samuel/My Projects/springsecurity/security/src/main/resources/verify.html";
    public static final String WELCOME_MAIL_TEMPLATE_LOCATION="/home/samuel/My Projects/springsecurity/security/src/main/resources/welcome.html";
    public static final String EMAIL_REGEX_STRING = "^[A-Za-z0-9+_._]+@(.+)$";
    public static final String ADMIN_INVITE_MAIL_TEMPLATE_LOCATION ="/home/samuel/My Projects/springsecurity/security/src/main/resources/adminMail.html";
    private static final String JSON_CONSTANT ="json";
    private static final String SAM_TECH_IMAGE = "/home/samuel/My Projects/springsecurity/security/src/main/resources/download.jpeg";

    public static String getMailTemplate(String templateLocation){
        try(BufferedReader reader = new BufferedReader(new FileReader(
                templateLocation))){
            return reader.lines().collect(Collectors.joining());
        } catch (IOException exception){
            throw new BusinessLogicException(exception.getMessage());
        }
    }

  public static String GET_EMAIL_VERIFICATION_MAIL_TEMPLATE = getMailTemplate(WELCOME_MAIL_TEMPLATE_LOCATION);



    public static String generaterRandomString(int length) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] randomBytes = new byte[length];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    public static @NotNull String generateVerificationOTP() {
        SecureRandom otp = new SecureRandom();
        return String.valueOf(otp.nextInt(1010, 10000));
    }





}
