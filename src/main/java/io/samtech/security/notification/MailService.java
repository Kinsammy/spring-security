package io.samtech.security.notification;

import io.samtech.security.data.dto.request.EmailNotificationRequest;

public interface MailService {
    String sendHtmlMail(EmailNotificationRequest request);
}
