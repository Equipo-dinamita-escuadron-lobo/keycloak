package com.security.keycloak.validation;

import java.util.regex.Pattern;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class StrongPasswordValidator implements ConstraintValidator<IStrongPassword, String> {

    private static final Pattern UPPERCASE_PATTERN = Pattern.compile(".*[A-Z].*");
    private static final Pattern LOWERCASE_PATTERN = Pattern.compile(".*[a-z].*");
    private static final Pattern DIGIT_PATTERN = Pattern.compile(".*\\d.*");
    private static final Pattern SPECIAL_CHAR_PATTERN = Pattern.compile(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?].*");

    @Override
    public void initialize(IStrongPassword constraintAnnotation) {
        // No initialization needed
    }

    @Override
    public boolean isValid(String password, ConstraintValidatorContext context) {
        if (password == null) {
            return false;
        }

        boolean hasUppercase = UPPERCASE_PATTERN.matcher(password).matches();
        boolean hasLowercase = LOWERCASE_PATTERN.matcher(password).matches();
        boolean hasDigit = DIGIT_PATTERN.matcher(password).matches();
        boolean hasSpecialChar = SPECIAL_CHAR_PATTERN.matcher(password).matches();

        if (!hasUppercase || !hasLowercase || !hasDigit || !hasSpecialChar) {
            context.disableDefaultConstraintViolation();
            
            StringBuilder messageBuilder = new StringBuilder("La contraseña debe contener ");
            if (!hasUppercase) messageBuilder.append("al menos una mayúscula, ");
            if (!hasLowercase) messageBuilder.append("al menos una minúscula, ");
            if (!hasDigit) messageBuilder.append("al menos un número, ");
            if (!hasSpecialChar) messageBuilder.append("al menos un carácter especial, ");
            
            // Remove trailing comma and space
            String message = messageBuilder.toString().trim();
            if (message.endsWith(",")) {
                message = message.substring(0, message.length() - 1);
            }
            
            context.buildConstraintViolationWithTemplate(message)
                   .addConstraintViolation();
            
            return false;
        }
        
        return true;
    }
}
