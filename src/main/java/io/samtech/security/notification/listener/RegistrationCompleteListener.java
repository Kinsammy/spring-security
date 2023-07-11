package io.samtech.security.notification.listener;

import io.samtech.security.data.dto.request.EmailNotificationRequest;
import io.samtech.security.data.dto.request.Recipient;
import io.samtech.security.data.models.user.User;
import io.samtech.security.notification.MailService;
import io.samtech.security.notification.event.RegistrationCompleteEvent;
import io.samtech.security.service.IVerificationTokenService;
import io.samtech.security.utils.AppUtilities;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class RegistrationCompleteListener implements ApplicationListener<RegistrationCompleteEvent> {
    private final IVerificationTokenService tokenService;
    private final MailService mailService;
    private User user;
    @Override
    public void onApplicationEvent(RegistrationCompleteEvent event) {
        user = event.getUser();
        String token = UUID.randomUUID().toString();
        tokenService.saveUserVerificationToken(user, token);
        String url = event.getApplicationUrl()+"/api/v1/auth/verify-email?token="+token;
        sendVerificationEmail(url);
    }

    public void sendVerificationEmail(String url) {
        EmailNotificationRequest request = new EmailNotificationRequest();
        request.setHtmlContent(AppUtilities.GET_EMAIL_VERIFICATION_MAIL_TEMPLATE + url);
        request.getTo().add(new Recipient(user.getName(), user.getEmail()));
        mailService.sendHtmlMail(request);
    }
}
