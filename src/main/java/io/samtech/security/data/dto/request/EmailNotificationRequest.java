package io.samtech.security.data.dto.request;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class EmailNotificationRequest {
    private final Sender sender = new Sender("SamTech", "noreply@samtech.net");
    private List<Recipient> to = new ArrayList<>();
    private final String subject = "Welcome to SamTech: Activate Your Account";
    private String htmlContent;
}
