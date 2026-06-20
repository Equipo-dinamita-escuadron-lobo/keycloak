package com.security.keycloak.audit.event;

import jakarta.servlet.http.HttpServletRequest;

public record UserLoggedOutEvent(String jwtToken, HttpServletRequest request) {

}
