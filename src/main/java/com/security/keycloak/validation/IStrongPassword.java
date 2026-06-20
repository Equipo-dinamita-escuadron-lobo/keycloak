package com.security.keycloak.validation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

@Target({ElementType.FIELD, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = StrongPasswordValidator.class)
public @interface IStrongPassword {
    String message() default "La contraseña debe contener al menos una mayúscula, una minúscula, un número y un carácter especial";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}
