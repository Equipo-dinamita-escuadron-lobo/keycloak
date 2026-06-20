package com.security.keycloak.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class SanitizeValidator implements ConstraintValidator<ISanitize, String> {

    @Override
    public void initialize(ISanitize constraintAnnotation) {
    }

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value == null) {
            return true;
        }
        String trimmed = value.trim();
        return !(trimmed.contains("<") || trimmed.contains(">") || trimmed.contains("&") ||
            trimmed.contains("\"") || trimmed.contains("'") || trimmed.contains("\\"));
    }
}
