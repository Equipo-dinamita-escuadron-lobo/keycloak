package com.security.keycloak.validation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

@Target({ElementType.FIELD, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = SanitizeValidator.class)
public @interface ISanitize {
    String message() default "Input contains invalid characters or needs sanitization";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}
