package com.security.keycloak.service;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.security.keycloak.dtos.AuthDTO;
import com.security.keycloak.dtos.UserDTO;

import jakarta.servlet.http.HttpServletRequest;

public interface IAuthKeycloakService {

    String getToken(AuthDTO authDTO, HttpServletRequest request) throws JsonMappingException, JsonProcessingException, RuntimeException;
    UserDTO getCurrentUser(String authorizationHeader) throws NoSuchAlgorithmException, InvalidKeySpecException;
    void logoutAndBlacklist(String authorizationHeader, HttpServletRequest request);
}
    