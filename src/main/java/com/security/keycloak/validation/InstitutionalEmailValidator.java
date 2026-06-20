package com.security.keycloak.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class InstitutionalEmailValidator implements ConstraintValidator<IInstitutionalEmail, String> {
  private String domain;
  @Override public void initialize(IInstitutionalEmail ann) { this.domain = ann.domain().toLowerCase(); }
  @Override public boolean isValid(String value, ConstraintValidatorContext ctx) {
    if (value == null) return false;
    return value.trim().toLowerCase().endsWith("@" + domain);
  }
}
