package com.security.keycloak.unitAudit.unitAuditSession;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.test.util.ReflectionTestUtils;

import com.security.keycloak.audit.message.dto.SessionEventDTO;
import com.security.keycloak.audit.message.util.IpAddressUtil;
import com.security.keycloak.audit.message.util.SessionEventBuilder;

import io.jsonwebtoken.Jwts;

@ExtendWith(MockitoExtension.class)
class AuditSessionEventBuilderTest {

    @Mock
    private IpAddressUtil ipAddressUtil;

    @Mock
    private HttpServletRequest request;

    private SessionEventBuilder builder;

    private KeyPair keyPair;

    @BeforeEach
    void setUp() throws Exception {
        keyPair = generateKeyPair();

        builder = new SessionEventBuilder(ipAddressUtil);

        String publicKeyBase64 = Base64.getEncoder()
                .encodeToString(keyPair.getPublic().getEncoded());

        ReflectionTestUtils.setField(builder, "publicKeyString", publicKeyBase64);

        when(ipAddressUtil.getClientIpAddress(request)).thenReturn("192.168.1.10");
    }

    @Test
    @DisplayName("buildLoginEvent - con JWT válido construye evento LOGIN")
    void buildLoginEvent_jwtValido() {
        String token = jwt(Map.of(
                "sub", "USER-1",
                "preferred_username", "maria",
                "sid", "SESSION-1",
                "realm_access", Map.of(
                        "roles", List.of("Administrador", "Profesor"))));

        SessionEventDTO result = builder.buildLoginEvent(token, request);

        assertEquals("SESSION-1", result.getSessionId());
        assertEquals("USER-1", result.getUserId());
        assertEquals("maria", result.getUserName());
        assertEquals(List.of("Administrador", "Profesor"), result.getUserRole());
        assertEquals("LOGIN", result.getAction());
        assertEquals("192.168.1.10", result.getIpAddress());
        assertNotNull(result.getActionAt());
        assertTrue(result.getActionAt().isBefore(Instant.now().plusSeconds(1)));
    }

    @Test
    @DisplayName("buildLogoutEvent - con JWT válido construye evento LOGOUT")
    void buildLogoutEvent_jwtValido() {
        String token = jwt(Map.of(
                "sub", "USER-1",
                "preferred_username", "maria",
                "sid", "SESSION-1"));

        SessionEventDTO result = builder.buildLogoutEvent(token, request);

        assertEquals("LOGOUT", result.getAction());
        assertEquals("SESSION-1", result.getSessionId());
        assertEquals("USER-1", result.getUserId());
        assertEquals("maria", result.getUserName());
        assertEquals("192.168.1.10", result.getIpAddress());
    }

    @Test
    @DisplayName("buildLoginEvent - si preferred_username es null usa email")
    void buildLoginEvent_sinPreferredUsernameUsaEmail() {
        String token = jwt(Map.of(
                "sub", "USER-1",
                "email", "maria@unicauca.edu.co",
                "sid", "SESSION-1"));

        SessionEventDTO result = builder.buildLoginEvent(token, request);

        assertEquals("maria@unicauca.edu.co", result.getUserName());
    }

    @Test
    @DisplayName("buildLoginEvent - si sid es null usa session_state")
    void buildLoginEvent_sinSidUsaSessionState() {
        String token = jwt(Map.of(
                "sub", "USER-1",
                "preferred_username", "maria",
                "session_state", "SESSION-STATE-1"));

        SessionEventDTO result = builder.buildLoginEvent(token, request);

        assertEquals("SESSION-STATE-1", result.getSessionId());
    }

    @Test
    @DisplayName("buildLoginEvent - si sid y session_state son null deja sessionId null")
    void buildLoginEvent_sinSessionId() {
        String token = jwt(Map.of(
                "sub", "USER-1",
                "preferred_username", "maria"));

        SessionEventDTO result = builder.buildLoginEvent(token, request);

        assertNull(result.getSessionId());
    }

    @Test
    @DisplayName("buildLoginEvent - filtra roles técnicos de Keycloak")
    void buildLoginEvent_filtraRolesTecnicos() {
        String token = jwt(Map.of(
                "sub", "USER-1",
                "preferred_username", "maria",
                "sid", "SESSION-1",
                "realm_access", Map.of(
                        "roles", List.of(
                                "Administrador",
                                "offline_access",
                                "default-roles-oauth2-realm",
                                "uma_authorization",
                                "Profesor"))));

        SessionEventDTO result = builder.buildLoginEvent(token, request);

        assertEquals(List.of("Administrador", "Profesor"), result.getUserRole());
    }

    @Test
    @DisplayName("buildLoginEvent - si realm_access es null retorna roles vacíos")
    void buildLoginEvent_realmAccessNull() {
        String token = jwt(Map.of(
                "sub", "USER-1",
                "preferred_username", "maria",
                "sid", "SESSION-1"));

        SessionEventDTO result = builder.buildLoginEvent(token, request);

        assertEquals(List.of(), result.getUserRole());
    }

    @Test
    @DisplayName("buildLoginEvent - si roles no es lista retorna roles vacíos")
    void buildLoginEvent_rolesNoEsLista() {
        String token = jwt(Map.of(
                "sub", "USER-1",
                "preferred_username", "maria",
                "sid", "SESSION-1",
                "realm_access", Map.of(
                        "roles", "Administrador")));

        SessionEventDTO result = builder.buildLoginEvent(token, request);

        assertEquals(List.of(), result.getUserRole());
    }

    @Test
    @DisplayName("buildLoginEvent - ignora roles que no son String")
    void buildLoginEvent_rolesNoString() {
        String token = jwt(Map.of(
                "sub", "USER-1",
                "preferred_username", "maria",
                "sid", "SESSION-1",
                "realm_access", Map.of(
                        "roles", List.of("Administrador", 123, true, "Profesor"))));

        SessionEventDTO result = builder.buildLoginEvent(token, request);

        assertEquals(List.of("Administrador", "Profesor"), result.getUserRole());
    }

    @Test
    @DisplayName("buildLoginEvent - token inválido retorna evento fallback LOGIN")
    void buildLoginEvent_tokenInvalidoFallback() {
        SessionEventDTO result = builder.buildLoginEvent("token-invalido", request);

        assertNull(result.getSessionId());
        assertNull(result.getUserId());
        assertNull(result.getUserName());
        assertNull(result.getUserRole());
        assertEquals("LOGIN", result.getAction());
        assertEquals("192.168.1.10", result.getIpAddress());
        assertNotNull(result.getActionAt());
    }

    @Test
    @DisplayName("buildLogoutEvent - token inválido retorna evento fallback LOGOUT")
    void buildLogoutEvent_tokenInvalidoFallback() {
        SessionEventDTO result = builder.buildLogoutEvent("token-invalido", request);

        assertNull(result.getSessionId());
        assertNull(result.getUserId());
        assertNull(result.getUserName());
        assertNull(result.getUserRole());
        assertEquals("LOGOUT", result.getAction());
        assertEquals("192.168.1.10", result.getIpAddress());
        assertNotNull(result.getActionAt());
    }

    @Test
    @DisplayName("buildLoginEvent - publicKey inválida retorna fallback")
    void buildLoginEvent_publicKeyInvalidaFallback() {
        ReflectionTestUtils.setField(builder, "publicKeyString", "clave-invalida");

        SessionEventDTO result = builder.buildLoginEvent("token", request);

        assertEquals("LOGIN", result.getAction());
        assertEquals("192.168.1.10", result.getIpAddress());
        assertNull(result.getUserId());
    }

    private KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private String jwt(Map<String, Object> claims) {
        return Jwts.builder()
                .claims(claims)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(keyPair.getPrivate(), Jwts.SIG.RS256)
                .compact();
    }
}
