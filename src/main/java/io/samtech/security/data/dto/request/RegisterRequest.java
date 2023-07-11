package io.samtech.security.data.dto.request;

import io.samtech.security.customAnnotation.email.ValidEmail;
import io.samtech.security.customAnnotation.password.PasswordMatches;
import io.samtech.security.data.models.user.Role;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@PasswordMatches
public class RegisterRequest {
    @NotNull
    @NotEmpty
    private String name;

    @ValidEmail
    @NotNull
    @NotEmpty
    private String email;
    @NotNull
    @NotEmpty
    private String password;
    private String matchingPassword;
    private Role role;


}
