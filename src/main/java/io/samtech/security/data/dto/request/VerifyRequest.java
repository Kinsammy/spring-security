package io.samtech.security.data.dto.request;

import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VerifyRequest {
    private String email;
    private String verificationToken;
}
