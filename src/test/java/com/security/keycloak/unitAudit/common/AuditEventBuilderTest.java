package com.security.keycloak.unitAudit.common;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import com.security.keycloak.audit.annotation.Auditable;
import com.security.keycloak.audit.annotation.OperationType;
import com.security.keycloak.audit.builder.AuditEventBuilder;
import com.security.keycloak.audit.builder.OperationEventDto;
import org.springframework.security.oauth2.jwt.Jwt;

class AuditEventBuilderTest {

    private AuditEventBuilder builder;

    @BeforeEach
    void setUp() {
        builder = new AuditEventBuilder();
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("build - sin autenticación debe usar identidad SYSTEM")
    void build_sinAutenticacionUsaSystem() {
        Auditable auditable = mockAuditable();

        Map<String, Object> dataObject = Map.of(
                "entity", Map.of("name", "Docente"));

        OperationEventDto result = builder.build(
                auditable,
                OperationType.CREATE,
                "REG-1",
                dataObject);

        assertEquals("SYSTEM", result.getEnterpriseId());
        assertEquals("SYSTEM", result.getUserId());
        assertEquals("SYSTEM", result.getUserName());
        assertEquals(List.of(), result.getUserRole());
        assertEquals("CREATE", result.getOperationType());
        assertEquals("CONFIGURATION", result.getModuleName());
        assertEquals("PROFILE", result.getAffectedTable());
        assertEquals("REG-1", result.getRegisterId());
        assertEquals(dataObject, result.getDataObject());
        assertNotNull(result.getOperationAt());
        assertTrue(result.getOperationAt().isBefore(Instant.now().plusSeconds(1)));
    }

    @Test
    @DisplayName("build - con JWT debe tomar subject y preferred_username")
    void build_conJwtUsaSubjectYPreferredUsername() {
        Auditable auditable = mockAuditable();

        Jwt jwt = jwt(Map.of(
                "sub", "USER-1",
                "preferred_username", "maria",
                "email", "maria@unicauca.edu.co",
                "realm_access", Map.of(
                        "roles", List.of("Administrador", "Profesor"))));

        SecurityContextHolder.getContext()
                .setAuthentication(new TestingAuthenticationToken(jwt, null));

        OperationEventDto result = builder.build(
                auditable,
                OperationType.UPDATE,
                "REG-1",
                Map.of("changes", Map.of("name", Map.of("before", "A", "after", "B"))));

        assertEquals("USER-1", result.getUserId());
        assertEquals("maria", result.getUserName());
        assertEquals(List.of("Administrador", "Profesor"), result.getUserRole());
        assertEquals("UPDATE", result.getOperationType());
    }

    @Test
    @DisplayName("build - si preferred_username es null debe usar email")
    void build_sinPreferredUsernameUsaEmail() {
        Auditable auditable = mockAuditable();

        Jwt jwt = jwt(Map.of(
                "sub", "USER-1",
                "email", "maria@unicauca.edu.co",
                "realm_access", Map.of(
                        "roles", List.of("Profesor"))));

        SecurityContextHolder.getContext()
                .setAuthentication(new TestingAuthenticationToken(jwt, null));

        OperationEventDto result = builder.build(
                auditable,
                OperationType.UPDATE,
                "REG-1",
                Map.of("changes", Map.of()));

        assertEquals("USER-1", result.getUserId());
        assertEquals("maria@unicauca.edu.co", result.getUserName());
        assertEquals(List.of("Profesor"), result.getUserRole());
    }

    @Test
    @DisplayName("build - debe filtrar roles técnicos de Keycloak")
    void build_filtraRolesTecnicos() {
        Auditable auditable = mockAuditable();

        Jwt jwt = jwt(Map.of(
                "sub", "USER-1",
                "preferred_username", "maria",
                "realm_access", Map.of(
                        "roles", List.of(
                                "Administrador",
                                "offline_access",
                                "uma_authorization",
                                "default-roles-oauth2-realm",
                                "Profesor"))));

        SecurityContextHolder.getContext()
                .setAuthentication(new TestingAuthenticationToken(jwt, null));

        OperationEventDto result = builder.build(
                auditable,
                OperationType.DELETE,
                "REG-1",
                Map.of("entity", Map.of("id", "REG-1")));

        assertEquals(List.of("Administrador", "Profesor"), result.getUserRole());
    }

    @Test
    @DisplayName("build - si realm_access es null retorna roles vacíos")
    void build_realmAccessNullRolesVacios() {
        Auditable auditable = mockAuditable();

        Jwt jwt = jwt(Map.of(
                "sub", "USER-1",
                "preferred_username", "maria"));

        SecurityContextHolder.getContext()
                .setAuthentication(new TestingAuthenticationToken(jwt, null));

        OperationEventDto result = builder.build(
                auditable,
                OperationType.CREATE,
                "REG-1",
                Map.of("entity", Map.of("name", "Docente")));

        assertEquals(List.of(), result.getUserRole());
    }

    @Test
    @DisplayName("build - si roles no es lista retorna roles vacíos")
    void build_rolesNoEsListaRolesVacios() {
        Auditable auditable = mockAuditable();

        Jwt jwt = jwt(Map.of(
                "sub", "USER-1",
                "preferred_username", "maria",
                "realm_access", Map.of(
                        "roles", "Administrador")));

        SecurityContextHolder.getContext()
                .setAuthentication(new TestingAuthenticationToken(jwt, null));

        OperationEventDto result = builder.build(
                auditable,
                OperationType.CREATE,
                "REG-1",
                Map.of("entity", Map.of("name", "Docente")));

        assertEquals(List.of(), result.getUserRole());
    }

    @Test
    @DisplayName("build - si extractRoles falla retorna roles vacíos")
    void build_extractRolesException_rolesVacios() {
        Auditable auditable = mockAuditable();
        Jwt jwt = mock(Jwt.class);
        when(jwt.getSubject()).thenReturn("USER-1");
        when(jwt.getClaimAsString("preferred_username"))
                .thenReturn("maria");
        when(jwt.getClaim("realm_access"))
                .thenThrow(new RuntimeException("boom"));
        SecurityContextHolder.getContext()
                .setAuthentication(new TestingAuthenticationToken(jwt, null));
        OperationEventDto result = builder.build(
                auditable,
                OperationType.CREATE,
                "REG-1",
                Map.of());

        assertEquals("USER-1", result.getUserId());
        assertEquals("maria", result.getUserName());

        assertEquals(List.of(), result.getUserRole());
    }

    @Test
    @DisplayName("build - si ocurre excepción leyendo JWT usa SYSTEM")
    void build_exceptionLeyendoJwt_usaSystem() {
        Auditable auditable = mockAuditable();
        Jwt jwt = mock(Jwt.class);
        when(jwt.getSubject())
                .thenThrow(new RuntimeException("boom"));
        SecurityContextHolder.getContext()
                .setAuthentication(new TestingAuthenticationToken(jwt, null));
        OperationEventDto result = builder.build(
                auditable,
                OperationType.CREATE,
                "REG-1",
                Map.of());
        assertEquals("SYSTEM", result.getUserId());
        assertEquals("SYSTEM", result.getUserName());
        assertEquals(List.of(), result.getUserRole());
    }

    @Test
    @DisplayName("build - si principal no es Jwt usa SYSTEM")
    void build_principalNoJwtUsaSystem() {
        Auditable auditable = mockAuditable();

        SecurityContextHolder.getContext()
                .setAuthentication(new TestingAuthenticationToken("usuario-plano", null));

        OperationEventDto result = builder.build(
                auditable,
                OperationType.CREATE,
                "REG-1",
                Map.of("entity", Map.of("name", "Docente")));

        assertEquals("SYSTEM", result.getUserId());
        assertEquals("SYSTEM", result.getUserName());
        assertEquals(List.of(), result.getUserRole());
    }

    private Auditable mockAuditable() {
        Auditable auditable = mock(Auditable.class);

        when(auditable.moduleName()).thenReturn("CONFIGURATION");
        when(auditable.affectedTable()).thenReturn("PROFILE");

        return auditable;
    }

    private Jwt jwt(Map<String, Object> claims) {
        return Jwt.withTokenValue("token")
                .header("alg", "none")
                .claims(c -> c.putAll(claims))
                .build();
    }
}
