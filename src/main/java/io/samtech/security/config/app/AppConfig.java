package io.samtech.security.config.app;

import io.samtech.security.config.mail.MailConfig;
import io.samtech.security.config.security.util.JwtSecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AppConfig {

    @Value("${sendinblue.api.key}")
    private String mailApiKey;
    @Value("${sendinblue.mail.url}")
    private String mailUrl;

    @Value("${application.security.jwt.secret-key}")
    private String jwtSecretKey;


    @Bean
    public MailConfig mailConfig(){
        return new MailConfig(mailApiKey, mailUrl);
    }



    @Bean
    public JwtSecretKey jwtSecretKey(){
        return new JwtSecretKey(jwtSecretKey);
    }
}
