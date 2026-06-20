package com.security.keycloak.unitAudit;

import static org.junit.jupiter.api.Assertions.assertEquals;

import static org.junit.jupiter.api.Assertions.assertTrue;

import static org.mockito.Mockito.when;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
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
import com.security.keycloak.audit.aspect.AuditAspectPermissions;
import com.security.keycloak.audit.builder.AuditEventBuilder;
import com.security.keycloak.audit.publisher.AuditEventPublisher;

import java.util.List;

@ExtendWith(MockitoExtension.class)
class AuditAspectPermissionsTest {

    @Mock
    private AuditEventBuilder auditEventBuilder;

    @Mock
    private AuditEventPublisher auditEventPublisher;

    @Mock
    private ProceedingJoinPoint joinPoint;

    private TestableAuditAspectPermissions aspect;

    @BeforeEach
    void setUp() {
        aspect = new TestableAuditAspectPermissions(
                auditEventBuilder,
                auditEventPublisher);
    }

    @Test
    @DisplayName("audit - debe delegar en executeAudit")
    void audit_debeDelegarEnExecuteAudit() throws Throwable {
        Auditable auditable = mockAuditable(OperationType.CREATE);

        when(joinPoint.getArgs()).thenReturn(new Object[] {
                List.of("Editar Impuestos"),
                "auditor"
        });
        when(joinPoint.proceed()).thenReturn(true);

        Object result = aspect.audit(joinPoint, auditable);

        assertEquals(true, result);
    }

    @Test
    @DisplayName("fetchCurrentState - siempre retorna mapa vacío")
    void fetchCurrentState_retornaVacio() {
        Auditable auditable = mockAuditable(OperationType.CREATE);

        Map<String, Object> result = aspect.testFetchCurrentState(
                auditable,
                new Object[] { List.of("Editar Impuestos"), "auditor" });

        assertTrue(result.isEmpty());
    }

    @Test
    @DisplayName("entityToMap - siempre retorna mapa vacío")
    void entityToMap_retornaVacio() {
        Map<String, Object> result = aspect.testEntityToMap(true);

        assertTrue(result.isEmpty());
    }

    @Test
    @DisplayName("entityToMap - con null retorna mapa vacío")
    void entityToMap_nullRetornaVacio() {
        Map<String, Object> result = aspect.testEntityToMap(null);

        assertTrue(result.isEmpty());
    }

    @Test
    @DisplayName("resolveRegisterId - toma roleName desde args[1]")
    void resolveRegisterId_ok() {
        Auditable auditable = mockAuditable(OperationType.CREATE);

        String result = aspect.testResolveRegisterId(
                auditable,
                new Object[] { List.of("Editar Impuestos"), "auditor" },
                true,
                Map.of());

        assertEquals("auditor", result);
    }

    @Test
    @DisplayName("resolveRegisterId - args null retorna UNKNOWN")
    void resolveRegisterId_argsNull() {
        Auditable auditable = mockAuditable(OperationType.CREATE);

        String result = aspect.testResolveRegisterId(
                auditable,
                null,
                true,
                Map.of());

        assertEquals("UNKNOWN", result);
    }

    @Test
    @DisplayName("resolveRegisterId - args vacío retorna UNKNOWN")
    void resolveRegisterId_argsVacio() {
        Auditable auditable = mockAuditable(OperationType.CREATE);

        String result = aspect.testResolveRegisterId(
                auditable,
                new Object[] {},
                true,
                Map.of());

        assertEquals("UNKNOWN", result);
    }

    @Test
    @DisplayName("resolveRegisterId - args sin posición 1 retorna UNKNOWN")
    void resolveRegisterId_sinArgUno() {
        Auditable auditable = mockAuditable(OperationType.CREATE);

        String result = aspect.testResolveRegisterId(
                auditable,
                new Object[] { List.of("Editar Impuestos") },
                true,
                Map.of());

        assertEquals("UNKNOWN", result);
    }

    @Test
    @DisplayName("resolveRegisterId - args[1] no String retorna UNKNOWN")
    void resolveRegisterId_argUnoNoString() {
        Auditable auditable = mockAuditable(OperationType.CREATE);

        String result = aspect.testResolveRegisterId(
                auditable,
                new Object[] { List.of("Editar Impuestos"), 123 },
                true,
                Map.of());

        assertEquals("UNKNOWN", result);
    }

    @Test
    @DisplayName("buildSpecialDataObject - construye entity con roleName y permisos")
    void buildSpecialDataObject_ok() {
        List<String> permissions = List.of(
                "Editar Impuestos",
                "Exportar Terceros");

        Map<String, Object> result = aspect.testBuildSpecialDataObject(
                OperationType.CREATE,
                new Object[] { permissions, "auditor" },
                true,
                Map.of());

        assertEquals("auditor", result.get("roleName"));
        assertEquals(permissions, result.get("permissions"));
    }

    @Test
    @DisplayName("buildSpecialDataObject - args null usa roleName UNKNOWN y permisos vacíos")
    void buildSpecialDataObject_argsNull() {
        Map<String, Object> result = aspect.testBuildSpecialDataObject(
                OperationType.CREATE,
                null,
                true,
                Map.of());

        assertEquals("UNKNOWN", result.get("roleName"));
        assertEquals(List.of(), result.get("permissions"));
    }

    @Test
    @DisplayName("buildSpecialDataObject - args vacío usa valores por defecto")
    void buildSpecialDataObject_argsVacio() {
        Map<String, Object> result = aspect.testBuildSpecialDataObject(
                OperationType.CREATE,
                new Object[] {},
                true,
                Map.of());

        assertEquals("UNKNOWN", result.get("roleName"));
        assertEquals(List.of(), result.get("permissions"));
    }

    @Test
    @DisplayName("buildSpecialDataObject - args[0] no List usa permisos vacíos")
    void buildSpecialDataObject_argCeroNoList() {
        Map<String, Object> result = aspect.testBuildSpecialDataObject(
                OperationType.CREATE,
                new Object[] { "no-es-lista", "auditor" },
                true,
                Map.of());

        assertEquals("auditor", result.get("roleName"));
        assertEquals(List.of(), result.get("permissions"));
    }

    @Test
    @DisplayName("buildSpecialDataObject - args[1] no String usa roleName UNKNOWN")
    void buildSpecialDataObject_argUnoNoString() {
        List<String> permissions = List.of("Editar Impuestos");

        Map<String, Object> result = aspect.testBuildSpecialDataObject(
                OperationType.CREATE,
                new Object[] { permissions, 123 },
                true,
                Map.of());

        assertEquals("UNKNOWN", result.get("roleName"));
        assertEquals(permissions, result.get("permissions"));
    }

    @Test
    @DisplayName("buildSpecialDataObject - sin args[1] usa roleName UNKNOWN")
    void buildSpecialDataObject_sinArgUno() {
        List<String> permissions = List.of("Editar Impuestos");

        Map<String, Object> result = aspect.testBuildSpecialDataObject(
                OperationType.CREATE,
                new Object[] { permissions },
                true,
                Map.of());

        assertEquals("UNKNOWN", result.get("roleName"));
        assertEquals(permissions, result.get("permissions"));
    }

    private Auditable mockAuditable(OperationType type) {
        Auditable auditable = mock(Auditable.class);

        lenient().when(auditable.operationType()).thenReturn(type);
        lenient().when(auditable.affectedTable()).thenReturn("PERMISSION");
        lenient().when(auditable.moduleName()).thenReturn("CONFIGURATION");

        return auditable;
    }

    private static class TestableAuditAspectPermissions extends AuditAspectPermissions {

        public TestableAuditAspectPermissions(
                AuditEventBuilder auditEventBuilder,
                AuditEventPublisher auditEventPublisher) {
            super(auditEventBuilder, auditEventPublisher);
        }

        Map<String, Object> testFetchCurrentState(Auditable auditable, Object[] args) {
            return fetchCurrentState(auditable, args);
        }

        Map<String, Object> testEntityToMap(Object object) {
            return entityToMap(object);
        }

        String testResolveRegisterId(
                Auditable auditable,
                Object[] args,
                Object result,
                Map<String, Object> beforeData) {
            return resolveRegisterId(auditable, args, result, beforeData);
        }

        Map<String, Object> testBuildSpecialDataObject(
                OperationType operationType,
                Object[] args,
                Object result,
                Map<String, Object> beforeData) {
            return buildSpecialDataObject(operationType, args, result, beforeData);
        }
    }
}
