package io.samtech.security.customAnnotation.password;

import io.samtech.security.data.dto.request.RegisterRequest;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class PasswordMatchesValidator implements ConstraintValidator<PasswordMatches, Object> {
    @Override
    public void initialize(PasswordMatches constraintAnnotation) {
        ConstraintValidator.super.initialize(constraintAnnotation);
    }

    @Override
    public boolean isValid(Object obj, ConstraintValidatorContext context) {
        RegisterRequest request = (RegisterRequest) obj;
        return request.getPassword().equals(request.getMatchingPassword());
    }
}
