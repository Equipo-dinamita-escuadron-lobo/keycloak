package com.security.keycloak.audit.message.util;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.security.keycloak.audit.message.dto.SessionEventDTO;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

@Component
@Slf4j
@RequiredArgsConstructor
public class SessionEventBuilder {

    private final IpAddressUtil ipAddressUtil;

    @Value("${jwt.public.key}")
    private String publicKeyString;

    public SessionEventDTO buildLoginEvent(String jwtToken, HttpServletRequest request) {
        return buildEvent(jwtToken, request, "LOGIN");
    }

    public SessionEventDTO buildLogoutEvent(String jwtToken, HttpServletRequest request) {
        return buildEvent(jwtToken, request, "LOGOUT");
    }

    private SessionEventDTO buildEvent(String jwtToken, HttpServletRequest request, String action) {
        try {
            PublicKey publicKey = getPublicKey(publicKeyString);
            Claims claims = Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(jwtToken)
                    .getPayload();

            String userId = claims.getSubject();
            String username = (String) claims.get("preferred_username");
            if (username == null) {
                username = (String) claims.get("email");
            }

            List<String> roles = extractRoles(claims);

            String sessionId = (String) claims.get("sid");
            if (sessionId == null) {
                sessionId = (String) claims.get("session_state");
            }

            return SessionEventDTO.builder()
                    .sessionId(sessionId)
                    .userId(userId)
                    .userName(username)
                    .userRole(roles)
                    .action(action)
                    .actionAt(Instant.now())
                    .ipAddress(ipAddressUtil.getClientIpAddress(request))
                    .build();

        } catch (Exception e) {
            log.error("Error building session event", e);
            return fallbackEvent(request, action);
        }
    }

    @SuppressWarnings("unchecked")
    private List<String> extractRoles(Claims claims) {

        Map<String, Object> realmAccess = (Map<String, Object>) claims.get("realm_access");

        if (realmAccess == null) {
            return List.of();
        }

        Object rolesObj = realmAccess.get("roles");

        if (!(rolesObj instanceof List<?> rolesList)) {
            return List.of();
        }

        return rolesList.stream()
                .filter(String.class::isInstance)
                .map(String.class::cast)
                .filter(r -> !r.equals("offline_access"))
                .filter(r -> !r.startsWith("default-roles-"))
                .filter(r -> !r.equals("uma_authorization"))
                .toList();
    }

    private SessionEventDTO fallbackEvent(HttpServletRequest request, String action) {
        return SessionEventDTO.builder()
                .action(action)
                .actionAt(Instant.now())
                .ipAddress(ipAddressUtil.getClientIpAddress(request))
                .build();
    }

    private PublicKey getPublicKey(String publicKeyString) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }
}
