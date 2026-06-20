package com.security.keycloak.unitAudit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import static org.junit.jupiter.api.Assertions.assertTrue;

import static org.mockito.Mockito.when;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import java.util.LinkedHashMap;
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
import com.security.keycloak.audit.aspect.AuditAspectProfiles;
import com.security.keycloak.audit.builder.AuditEventBuilder;
import com.security.keycloak.audit.publisher.AuditEventPublisher;
import com.security.keycloak.dtos.ProfileDTO;
import com.security.keycloak.service.IProfileKeycloakService;

@ExtendWith(MockitoExtension.class)
class AuditAspectProfilesTest {

    @Mock
    private AuditEventBuilder auditEventBuilder;

    @Mock
    private AuditEventPublisher auditEventPublisher;

    @Mock
    private IProfileKeycloakService profileKeycloakService;

    @Mock
    private ProceedingJoinPoint joinPoint;

    private TestableAuditAspectProfiles aspect;

    @BeforeEach
    void setUp() {
        aspect = new TestableAuditAspectProfiles(
                auditEventBuilder,
                auditEventPublisher,
                profileKeycloakService);
    }

    // -------------------------------------------------------------------------
    // audit
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("audit - debe delegar en executeAudit")
    void audit_debeDelegarEnExecuteAudit() throws Throwable {
        Auditable auditable = mockAuditable(OperationType.CREATE);

        ProfileDTO profile = ProfileDTO.builder()
                .id("PROFILE-1")
                .name("Docente")
                .description("Perfil docente")
                .build();

        when(joinPoint.getArgs()).thenReturn(new Object[] {});
        when(joinPoint.proceed()).thenReturn(profile);

        Object result = aspect.audit(joinPoint, auditable);

        assertEquals(profile, result);
    }

    @Test
    @DisplayName("fetchCurrentState - CREATE retorna mapa vacío y no consulta servicio")
    void fetchCurrentState_createRetornaVacio() {
        Auditable auditable = mockAuditable(OperationType.CREATE);

        Map<String, Object> result = aspect.testFetchCurrentState(
                auditable,
                new Object[] { "PROFILE-1" });

        assertTrue(result.isEmpty());
        verifyNoInteractions(profileKeycloakService);
    }

    @Test
    @DisplayName("fetchCurrentState - UPDATE consulta perfil por id y lo mapea")
    void fetchCurrentState_updateOk() {
        Auditable auditable = mockAuditable(OperationType.UPDATE);

        ProfileDTO profile = ProfileDTO.builder()
                .id("PROFILE-1")
                .name("Docente")
                .description("Perfil docente")
                .build();

        when(profileKeycloakService.findProfileById("PROFILE-1")).thenReturn(profile);

        Map<String, Object> result = aspect.testFetchCurrentState(
                auditable,
                new Object[] { "PROFILE-1" });

        assertEquals("Docente", result.get("name"));
        assertEquals("Perfil docente", result.get("description"));
        assertFalse(result.containsKey("id"));

        verify(profileKeycloakService).findProfileById("PROFILE-1");
    }

    @Test
    @DisplayName("fetchCurrentState - DELETE consulta perfil por id y lo mapea")
    void fetchCurrentState_deleteOk() {
        Auditable auditable = mockAuditable(OperationType.DELETE);

        ProfileDTO profile = ProfileDTO.builder()
                .id("PROFILE-1")
                .name("Director")
                .description("Dirección académica")
                .build();

        when(profileKeycloakService.findProfileById("PROFILE-1")).thenReturn(profile);

        Map<String, Object> result = aspect.testFetchCurrentState(
                auditable,
                new Object[] { "PROFILE-1" });

        assertEquals("Director", result.get("name"));
        assertEquals("Dirección académica", result.get("description"));

        verify(profileKeycloakService).findProfileById("PROFILE-1");
    }

    @Test
    @DisplayName("fetchCurrentState - si servicio falla retorna mapa vacío")
    void fetchCurrentState_errorRetornaVacio() {
        Auditable auditable = mockAuditable(OperationType.UPDATE);

        when(profileKeycloakService.findProfileById("PROFILE-1"))
                .thenThrow(new RuntimeException("Keycloak caído"));

        Map<String, Object> result = aspect.testFetchCurrentState(
                auditable,
                new Object[] { "PROFILE-1" });

        assertTrue(result.isEmpty());
    }

    @Test
    @DisplayName("entityToMap - mapea profile válido sin id")
    void entityToMap_profileValido() {
        ProfileDTO profile = ProfileDTO.builder()
                .id("PROFILE-1")
                .name("Docente")
                .description("Perfil docente")
                .build();

        Map<String, Object> result = aspect.testEntityToMap(profile);

        assertEquals(2, result.size());
        assertEquals("Docente", result.get("name"));
        assertEquals("Perfil docente", result.get("description"));
        assertFalse(result.containsKey("id"));
    }

    @Test
    @DisplayName("entityToMap - remueve campos null")
    void entityToMap_remueveNulls() {
        ProfileDTO profile = ProfileDTO.builder()
                .id("PROFILE-1")
                .name("Docente")
                .description(null)
                .build();

        Map<String, Object> result = aspect.testEntityToMap(profile);

        assertEquals(1, result.size());
        assertEquals("Docente", result.get("name"));
        assertFalse(result.containsKey("description"));
    }

    @Test
    @DisplayName("entityToMap - profile con todos los campos null retorna vacío")
    void entityToMap_todosNullRetornaVacio() {
        ProfileDTO profile = ProfileDTO.builder()
                .id("PROFILE-1")
                .name(null)
                .description(null)
                .build();

        Map<String, Object> result = aspect.testEntityToMap(profile);

        assertTrue(result.isEmpty());
    }

    @Test
    @DisplayName("entityToMap - objeto inválido retorna mapa vacío")
    void entityToMap_objetoInvalido() {
        Map<String, Object> result = aspect.testEntityToMap("no-es-profile");

        assertTrue(result.isEmpty());
    }

    @Test
    @DisplayName("buildContext - incluye profileName cuando name existe")
    void buildContext_conName() {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("name", "Docente");
        data.put("description", "Perfil docente");

        Map<String, Object> result = aspect.testBuildContext(data);

        assertEquals(1, result.size());
        assertEquals("Docente", result.get("profileName"));
    }

    @Test
    @DisplayName("buildContext - sin name retorna vacío")
    void buildContext_sinName() {
        Map<String, Object> data = Map.of("description", "Perfil docente");

        Map<String, Object> result = aspect.testBuildContext(data);

        assertTrue(result.isEmpty());
    }

    @Test
    @DisplayName("buildContext - data null retorna vacío")
    void buildContext_dataNull() {
        Map<String, Object> result = aspect.testBuildContext(null);

        assertTrue(result.isEmpty());
    }

    @Test
    @DisplayName("buildContext - data vacía retorna vacío")
    void buildContext_dataVacia() {
        Map<String, Object> result = aspect.testBuildContext(Map.of());

        assertTrue(result.isEmpty());
    }

    @Test
    @DisplayName("resolveRegisterId - CREATE toma id del resultado")
    void resolveRegisterId_createOk() {
        Auditable auditable = mockAuditable(OperationType.CREATE);

        ProfileDTO profile = ProfileDTO.builder()
                .id("PROFILE-1")
                .build();

        String result = aspect.testResolveRegisterId(
                auditable,
                new Object[] {},
                profile,
                null);

        assertEquals("PROFILE-1", result);
    }

    @Test
    @DisplayName("resolveRegisterId - CREATE sin ProfileDTO retorna UNKNOWN")
    void resolveRegisterId_createSinProfileDto() {
        Auditable auditable = mockAuditable(OperationType.CREATE);

        String result = aspect.testResolveRegisterId(
                auditable,
                new Object[] {},
                "resultado-no-valido",
                null);

        assertEquals("UNKNOWN", result);
    }

    @Test
    @DisplayName("resolveRegisterId - UPDATE toma args[0]")
    void resolveRegisterId_updateOk() {
        Auditable auditable = mockAuditable(OperationType.UPDATE);

        String result = aspect.testResolveRegisterId(
                auditable,
                new Object[] { "PROFILE-1" },
                null,
                null);

        assertEquals("PROFILE-1", result);
    }

    @Test
    @DisplayName("resolveRegisterId - DELETE toma args[0]")
    void resolveRegisterId_deleteOk() {
        Auditable auditable = mockAuditable(OperationType.DELETE);

        String result = aspect.testResolveRegisterId(
                auditable,
                new Object[] { "PROFILE-1" },
                null,
                null);

        assertEquals("PROFILE-1", result);
    }

    @Test
    @DisplayName("resolveRegisterId - UPDATE sin args retorna UNKNOWN")
    void resolveRegisterId_updateSinArgs() {
        Auditable auditable = mockAuditable(OperationType.UPDATE);

        String result = aspect.testResolveRegisterId(
                auditable,
                new Object[] {},
                null,
                null);

        assertEquals("UNKNOWN", result);
    }

    @Test
    @DisplayName("resolveRegisterId - UPDATE con args null retorna UNKNOWN")
    void resolveRegisterId_updateArgsNull() {
        Auditable auditable = mockAuditable(OperationType.UPDATE);

        String result = aspect.testResolveRegisterId(
                auditable,
                null,
                null,
                null);

        assertEquals("UNKNOWN", result);
    }

    @Test
    @DisplayName("resolveRegisterId - UPDATE con args[0] no String retorna UNKNOWN")
    void resolveRegisterId_updateArgNoString() {
        Auditable auditable = mockAuditable(OperationType.UPDATE);

        String result = aspect.testResolveRegisterId(
                auditable,
                new Object[] { 123 },
                null,
                null);

        assertEquals("UNKNOWN", result);
    }

    @Test
    @DisplayName("resolveRegisterId - operación no soportada retorna UNKNOWN")
    void resolveRegisterId_default() {
        Auditable auditable = mockAuditable(OperationType.RESET_PASSWORD);

        String result = aspect.testResolveRegisterId(
                auditable,
                new Object[] { "PROFILE-1" },
                null,
                null);

        assertEquals("UNKNOWN", result);
    }

    // Helper
    private Auditable mockAuditable(OperationType type) {
        Auditable auditable = mock(Auditable.class);

        lenient().when(auditable.operationType()).thenReturn(type);
        lenient().when(auditable.affectedTable()).thenReturn("PROFILE");
        lenient().when(auditable.moduleName()).thenReturn("CONFIGURATION");

        return auditable;
    }

    private static class TestableAuditAspectProfiles extends AuditAspectProfiles {

        public TestableAuditAspectProfiles(
                AuditEventBuilder auditEventBuilder,
                AuditEventPublisher auditEventPublisher,
                IProfileKeycloakService profileKeycloakService) {
            super(auditEventBuilder, auditEventPublisher, profileKeycloakService);
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
