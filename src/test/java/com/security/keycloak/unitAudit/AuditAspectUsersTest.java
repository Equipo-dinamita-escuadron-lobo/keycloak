package com.security.keycloak.unitAudit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

import static org.junit.jupiter.api.Assertions.assertTrue;

import static org.mockito.Mockito.when;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.aspectj.lang.ProceedingJoinPoint;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.security.keycloak.audit.annotation.Auditable;
import com.security.keycloak.audit.annotation.OperationType;
import com.security.keycloak.audit.aspect.AuditAspectUsers;
import com.security.keycloak.audit.builder.AuditEventBuilder;
import com.security.keycloak.audit.publisher.AuditEventPublisher;
import com.security.keycloak.dtos.UserDTO;
import com.security.keycloak.service.IUserKeycloakService;

@ExtendWith(MockitoExtension.class)
class AuditAspectUsersTest {

    @Mock
    private AuditEventBuilder auditEventBuilder;

    @Mock
    private AuditEventPublisher auditEventPublisher;

    @Mock
    private IUserKeycloakService userKeycloakService;

    @Mock
    private ProceedingJoinPoint joinPoint;

    private TestableAuditAspectUsers aspect;

    @BeforeEach
    void setUp() {
        aspect = new TestableAuditAspectUsers(
                auditEventBuilder,
                auditEventPublisher,
                userKeycloakService);
    }

    // -------------------------------------------------------------------------
    // audit
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("audit - debe delegar en executeAudit")
    void audit_debeDelegarEnExecuteAudit() throws Throwable {
        Auditable auditable = mockAuditable(OperationType.CREATE);

        UserDTO user = UserDTO.builder()
                .id("USER-1")
                .email("test@unicauca.edu.co")
                .firstName("Test")
                .lastName("User")
                .roles(List.of("Administrador"))
                .build();

        when(joinPoint.getArgs()).thenReturn(new Object[] {});
        when(joinPoint.proceed()).thenReturn(user);

        Object result = aspect.audit(joinPoint, auditable);

        assertEquals(user, result);
    }

    @Test
    @DisplayName("fetchCurrentState - debe obtener usuario por id y mapearlo")
    void fetchCurrentState_ok() {
        Auditable auditable = mockAuditable(OperationType.UPDATE);

        UserDTO user = UserDTO.builder()
                .id("USER-1")
                .email("maria@unicauca.edu.co")
                .firstName("Maria")
                .lastName("CM")
                .roles(List.of("Profesor"))
                .build();

        when(userKeycloakService.findUserById("USER-1")).thenReturn(user);

        Map<String, Object> result = aspect.testFetchCurrentState(
                auditable,
                new Object[] { "USER-1" });

        assertEquals("maria@unicauca.edu.co", result.get("email"));
        assertEquals("Maria", result.get("firstName"));
        assertEquals("CM", result.get("lastName"));
        assertEquals(List.of("Profesor"), result.get("roles"));

        verify(userKeycloakService).findUserById("USER-1");
    }

    @Test
    @DisplayName("fetchCurrentState - si falla retorna null")
    void fetchCurrentState_errorRetornaNull() {
        Auditable auditable = mockAuditable(OperationType.UPDATE);

        when(userKeycloakService.findUserById("USER-1"))
                .thenThrow(new RuntimeException("Keycloak caído"));

        Map<String, Object> result = aspect.testFetchCurrentState(
                auditable,
                new Object[] { "USER-1" });

        assertNull(result);
    }

    @Test
    @DisplayName("entityToMap - debe mapear usuario sin password ni username")
    void entityToMap_usuarioValido() {
        UserDTO user = UserDTO.builder()
                .id("USER-1")
                .username("no-se-audita")
                .email("maria@unicauca.edu.co")
                .firstName("Maria")
                .lastName("CM")
                .password("123456")
                .roles(List.of("Profesor"))
                .build();

        Map<String, Object> result = aspect.testEntityToMap(user);

        assertEquals(4, result.size());
        assertEquals("maria@unicauca.edu.co", result.get("email"));
        assertEquals("Maria", result.get("firstName"));
        assertEquals("CM", result.get("lastName"));
        assertEquals(List.of("Profesor"), result.get("roles"));

        assertFalse(result.containsKey("id"));
        assertFalse(result.containsKey("username"));
        assertFalse(result.containsKey("password"));
    }

    @Test
    @DisplayName("entityToMap - debe limpiar roles técnicos, repetidos y null")
    void entityToMap_limpiaRolesTecnicos() {
        UserDTO user = UserDTO.builder()
                .email("user@unicauca.edu.co")
                .roles(Arrays.asList(
                        "Profesor",
                        "offline_access",
                        "uma_authorization",
                        "default-roles-keycloak",
                        "Administrador",
                        "Profesor",
                        null))
                .build();

        Map<String, Object> result = aspect.testEntityToMap(user);

        assertEquals(List.of("Administrador", "Profesor"), result.get("roles"));
    }

    @Test
    @DisplayName("entityToMap - si roles es null debe dejar lista vacía")
    void entityToMap_rolesNull() {
        UserDTO user = UserDTO.builder()
                .email("user@unicauca.edu.co")
                .roles(null)
                .build();

        Map<String, Object> result = aspect.testEntityToMap(user);

        assertEquals(List.of(), result.get("roles"));
    }

    @Test
    @DisplayName("entityToMap - debe remover campos null excepto roles")
    void entityToMap_remueveCamposNull() {
        UserDTO user = UserDTO.builder()
                .email(null)
                .firstName(null)
                .lastName("Perez")
                .roles(null)
                .build();

        Map<String, Object> result = aspect.testEntityToMap(user);

        assertFalse(result.containsKey("email"));
        assertFalse(result.containsKey("firstName"));
        assertEquals("Perez", result.get("lastName"));
        assertEquals(List.of(), result.get("roles"));
    }

    @Test
    @DisplayName("entityToMap - objeto inválido retorna mapa vacío")
    void entityToMap_objetoInvalido() {
        Map<String, Object> result = aspect.testEntityToMap("no-es-user");

        assertTrue(result.isEmpty());
    }

    @Test
    @DisplayName("buildContext - debe incluir email si existe")
    void buildContext_conEmail() {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("email", "user@unicauca.edu.co");
        data.put("firstName", "Usuario");

        Map<String, Object> context = aspect.testBuildContext(data);

        assertEquals(1, context.size());
        assertEquals("user@unicauca.edu.co", context.get("email"));
    }

    @Test
    @DisplayName("buildContext - sin email retorna vacío")
    void buildContext_sinEmail() {
        Map<String, Object> data = Map.of("firstName", "Usuario");

        Map<String, Object> context = aspect.testBuildContext(data);

        assertTrue(context.isEmpty());
    }

    @Test
    @DisplayName("buildContext - data null retorna vacío")
    void buildContext_dataNull() {
        Map<String, Object> context = aspect.testBuildContext(null);

        assertTrue(context.isEmpty());
    }

    @Test
    @DisplayName("resolveRegisterId - CREATE toma id del resultado")
    void resolveRegisterId_create() {
        Auditable auditable = mockAuditable(OperationType.CREATE);

        UserDTO user = UserDTO.builder()
                .id("USER-1")
                .build();

        String id = aspect.testResolveRegisterId(
                auditable,
                new Object[] {},
                user,
                null);

        assertEquals("USER-1", id);
    }

    @Test
    @DisplayName("resolveRegisterId - CREATE sin UserDTO retorna UNKNOWN")
    void resolveRegisterId_createSinUserDto() {
        Auditable auditable = mockAuditable(OperationType.CREATE);

        String id = aspect.testResolveRegisterId(
                auditable,
                new Object[] {},
                "resultado-no-valido",
                null);

        assertEquals("UNKNOWN", id);
    }

    @Test
    @DisplayName("resolveRegisterId - UPDATE toma args[0]")
    void resolveRegisterId_update() {
        Auditable auditable = mockAuditable(OperationType.UPDATE);

        String id = aspect.testResolveRegisterId(
                auditable,
                new Object[] { "USER-1" },
                null,
                null);

        assertEquals("USER-1", id);
    }

    @Test
    @DisplayName("resolveRegisterId - DELETE toma args[0]")
    void resolveRegisterId_delete() {
        Auditable auditable = mockAuditable(OperationType.DELETE);

        String id = aspect.testResolveRegisterId(
                auditable,
                new Object[] { "USER-1" },
                null,
                null);

        assertEquals("USER-1", id);
    }

    @Test
    @DisplayName("resolveRegisterId - operación no soportada retorna UNKNOWN")
    void resolveRegisterId_default() {
        Auditable auditable = mockAuditable(OperationType.RESET_PASSWORD);

        String id = aspect.testResolveRegisterId(
                auditable,
                new Object[] { "USER-1" },
                null,
                null);

        assertEquals("UNKNOWN", id);
    }

    private Auditable mockAuditable(OperationType type) {
        Auditable auditable = mock(Auditable.class);

        lenient().when(auditable.operationType()).thenReturn(type);
        lenient().when(auditable.affectedTable()).thenReturn("USER");
        lenient().when(auditable.moduleName()).thenReturn("CONFIGURATION");

        return auditable;
    }

    private static class TestableAuditAspectUsers extends AuditAspectUsers {

        public TestableAuditAspectUsers(
                AuditEventBuilder auditEventBuilder,
                AuditEventPublisher auditEventPublisher,
                IUserKeycloakService userKeycloakService) {
            super(auditEventBuilder, auditEventPublisher, userKeycloakService);
        }

        Map<String, Object> testFetchCurrentState(Auditable auditable, Object[] args) {
            return fetchCurrentState(auditable, args);
        }

        Map<String, Object> testEntityToMap(Object object) {
            return entityToMap(object);
        }

        Map<String, Object> testBuildContext(Map<String, Object> data) {
            return buildContext(data);
        }

        String testResolveRegisterId(
                Auditable auditable,
                Object[] args,
                Object result,
                Map<String, Object> beforeData) {
            return resolveRegisterId(auditable, args, result, beforeData);
        }
    }
}