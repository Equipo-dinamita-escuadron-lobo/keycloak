package com.security.keycloak.audit.event;

import jakarta.servlet.http.HttpServletRequest;

public record UserLoggedInEvent(String jwtToken, HttpServletRequest request) {
}
