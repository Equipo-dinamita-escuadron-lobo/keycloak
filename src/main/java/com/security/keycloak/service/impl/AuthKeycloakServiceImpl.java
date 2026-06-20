package com.security.keycloak.service.impl;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.keycloak.audit.event.UserLoggedInEvent;
import com.security.keycloak.audit.event.UserLoggedOutEvent;
import com.security.keycloak.controller.exception.UserException;
import com.security.keycloak.dtos.AuthDTO;
import com.security.keycloak.dtos.UserDTO;
import com.security.keycloak.service.IAuthKeycloakService;
import com.security.keycloak.util.JwtUtils;
import com.security.keycloak.util.KeycloakProvider;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthKeycloakServiceImpl implements IAuthKeycloakService {

    private static final Logger logger = LoggerFactory.getLogger(AuthKeycloakServiceImpl.class);

    private final StringRedisTemplate redis;
    private final KeycloakProvider keycloakProvider;

    private final ApplicationEventPublisher eventPublisher;

    @Value("${app.jwt.blacklist-prefix:jwt:black:}")
    private String blacklistPrefix;

    @Value("${keycloak.client.secret}")
    private String CLIENT_SECRET;

    @Value("${jwt.token.url}")
    private String tokenUrl;

    @Value("${jwt.auth.converter.resource-id}")
    private String CLIENT_ID;

    @Value("${jwt.public.key}")
    private String publicKeyString;

    @Override
    public UserDTO getCurrentUser(String authorizationHeader) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String jwt = null;
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            jwt = authorizationHeader.substring(7);
        }

        if (jwt == null) {
            throw new UserException("No autorizado", 401);
        }

        try {
            PublicKey publicKey = getPublicKey(publicKeyString);
            Claims claims = Jwts.parser().setSigningKey(publicKey).build().parseClaimsJws(jwt).getBody();

            @SuppressWarnings("unchecked")
            UserDTO user = UserDTO.builder()
                    .id(claims.get("sub").toString())
                    .username(claims.get("preferred_username").toString())
                    .email("** email **")
                    .firstName(claims.get("given_name").toString())
                    .lastName(claims.get("family_name").toString())
                    .roles((List<String>) (((Map<String, Object>) claims.get("realm_access"))).get("roles"))
                    .build();

            return user;
        } catch (Exception e) {
            logger.warn("Token inválido: {}", e.getMessage());
            throw new UserException("Token inválido", 401);
        }
    }

    private PublicKey getPublicKey(String publicKeyString) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    @Override
    public void logoutAndBlacklist(String authHeader, HttpServletRequest request) {
        String token = (authHeader != null && authHeader.startsWith("Bearer ")) ? authHeader.substring(7) : null;
        if (token == null)
            return;
        keycloakProvider.revoke(token);
        String jti = JwtUtils.getJti(token);
        long ttl = JwtUtils.getTtlSeconds(token);
        if (jti != null && ttl > 0) {
            redis.opsForValue().set(blacklistPrefix + jti, "1", java.time.Duration.ofSeconds(ttl));
        }
        // Publico evento de logout para micro de auditoria
        eventPublisher.publishEvent(new UserLoggedOutEvent(token, request));
    }

    @SuppressWarnings("unchecked")
    @Override
    public String getToken(AuthDTO authDTO, HttpServletRequest request)
            throws JsonMappingException, JsonProcessingException {

        try {
            MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
            formData.add("client_id", CLIENT_ID);
            formData.add("grant_type", "password");
            formData.add("username", authDTO.getUsername());
            formData.add("password", authDTO.getPassword());
            formData.add("client_secret", CLIENT_SECRET);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, headers);

            ResponseEntity<String> response = new RestTemplate().postForEntity(tokenUrl, requestEntity, String.class);

            String responseBody = response.getBody();

            ObjectMapper mapper = new ObjectMapper();
            Map<String, Object> responseMap = mapper.readValue(responseBody, Map.class);
            String accessToken = (String) responseMap.get("access_token");

            // Check if user is enabled
            String userId = JwtUtils.getSub(accessToken);
            if (userId != null) {
                var userRep = keycloakProvider.getUserResource().get(userId).toRepresentation();
                if (!userRep.isEnabled()) {
                    throw new UserException("Usuario inactivo", 401);
                }
            }

            String rptToken = getTokenRPT(accessToken);

            Object expiresInObject = responseMap.get("expires_in");
            Object refreshExpires = responseMap.get("refresh_expires_in");

            Map<String, Object> accessTokenInfo = new HashMap<>();
            accessTokenInfo.put("access_token", rptToken);
            accessTokenInfo.put("expires_in", expiresInObject);
            accessTokenInfo.put("refresh_expires_in", refreshExpires);

            String accessTokenJson = mapper.writeValueAsString(accessTokenInfo);

            // Publico evento de token para micro de auditoria
            eventPublisher.publishEvent(new UserLoggedInEvent(rptToken, request));

            return accessTokenJson;
        } catch (RestClientException e) {
            logger.warn("Intento de login fallido para usuario: {}", authDTO.getUsername());
            throw new UserException("Credenciales inválidas", 401);
        } catch (Exception e) {
            logger.error("Error interno en getToken para usuario: {}", authDTO.getUsername(), e);
            throw new UserException("Error interno en autenticación", 500);
        }
    }

    @SuppressWarnings("unchecked")
    public String getTokenRPT(String token) throws JsonMappingException, JsonProcessingException {

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket");
        formData.add("audience", CLIENT_ID);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.set("Authorization", "Bearer " + token);

        HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, headers);

        ResponseEntity<String> response = new RestTemplate().postForEntity(tokenUrl, requestEntity, String.class);

        String responseBody = response.getBody();

        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object> responseMap = mapper.readValue(responseBody, Map.class);
        String accessToken = (String) responseMap.get("access_token");

        return accessToken;
    }
}
