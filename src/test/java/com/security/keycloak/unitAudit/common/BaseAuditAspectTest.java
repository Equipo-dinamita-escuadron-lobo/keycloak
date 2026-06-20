package com.security.keycloak.unitAudit.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.ArgumentMatchers.anyMap;

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
import com.security.keycloak.audit.aspect.BaseAuditAspect;
import com.security.keycloak.audit.builder.AuditEventBuilder;
import com.security.keycloak.audit.builder.OperationEventDto;
import com.security.keycloak.audit.publisher.AuditEventPublisher;

@ExtendWith(MockitoExtension.class)
class BaseAuditAspectTest {

    @Mock
    private AuditEventBuilder auditEventBuilder;

    @Mock
    private AuditEventPublisher auditEventPublisher;

    @Mock
    private ProceedingJoinPoint joinPoint;

    @Mock
    private OperationEventDto operationEventDto;

    private TestableBaseAuditAspect aspect;

    private Map<String, Object> stubbedCurrentState;
    private Map<String, Object> stubbedEntityMap;
    private boolean throwOnFetchCurrentState;
    private boolean throwOnBuildDataObject;
    private Map<String, Object> specialDataObject;

    @BeforeEach
    void setUp() {
        stubbedCurrentState = null;
        stubbedEntityMap = null;
        throwOnFetchCurrentState = false;
        throwOnBuildDataObject = false;
        specialDataObject = Map.of();

        aspect = new TestableBaseAuditAspect(auditEventBuilder, auditEventPublisher);
    }

    @Test
    @DisplayName("buildDiff - debe detectar campos cambiados")
    void buildDiff_camposCambiados() {
        Map<String, Object> before = Map.of(
                "name", "Docente",
                "description", "Perfil anterior");

        Map<String, Object> after = Map.of(
                "name", "Director",
                "description", "Perfil anterior");

        Map<String, Object> diff = aspect.testBuildDiff(before, after);

        assertEquals(1, diff.size());
        assertTrue(diff.containsKey("name"));

        Map<?, ?> nameChange = (Map<?, ?>) diff.get("name");
        assertEquals("Docente", nameChange.get("before"));
        assertEquals("Director", nameChange.get("after"));
    }

    @Test
    @DisplayName("buildDiff - debe retornar vacío si no hay cambios")
    void buildDiff_sinCambios() {
        Map<String, Object> before = Map.of("name", "Docente");
        Map<String, Object> after = Map.of("name", "Docente");

        Map<String, Object> diff = aspect.testBuildDiff(before, after);

        assertTrue(diff.isEmpty());
    }

    @Test
    @DisplayName("buildDiff - debe retornar vacío si before es null")
    void buildDiff_beforeNull() {
        Map<String, Object> after = Map.of("name", "Docente");

        Map<String, Object> diff = aspect.testBuildDiff(null, after);

        assertTrue(diff.isEmpty());
    }

    @Test
    @DisplayName("buildDiff - debe retornar vacío si after es null")
    void buildDiff_afterNull() {
        Map<String, Object> before = Map.of("name", "Docente");

        Map<String, Object> diff = aspect.testBuildDiff(before, null);

        assertTrue(diff.isEmpty());
    }

    @Test
    @DisplayName("captureBeforeData - CREATE no debe consultar estado previo")
    void captureBeforeData_createRetornaNull() {
        Auditable auditable = mockAuditable(OperationType.CREATE);

        Map<String, Object> result = aspect.testCaptureBeforeData(auditable, new Object[] { "ID-1" });

        assertNull(result);
    }

    @Test
    @DisplayName("captureBeforeData - UPDATE debe consultar estado previo")
    void captureBeforeData_updateRetornaEstadoPrevio() {
        Auditable auditable = mockAuditable(OperationType.UPDATE);
        stubbedCurrentState = Map.of("name", "Docente");

        Map<String, Object> result = aspect.testCaptureBeforeData(auditable, new Object[] { "ID-1" });

        assertEquals(stubbedCurrentState, result);
    }

    @Test
    @DisplayName("captureBeforeData - DELETE debe consultar estado previo")
    void captureBeforeData_deleteRetornaEstadoPrevio() {
        Auditable auditable = mockAuditable(OperationType.DELETE);
        stubbedCurrentState = Map.of("name", "Docente");

        Map<String, Object> result = aspect.testCaptureBeforeData(auditable, new Object[] { "ID-1" });

        assertEquals(stubbedCurrentState, result);
    }

    @Test
    @DisplayName("captureBeforeData - si fetchCurrentState falla retorna null")
    void captureBeforeData_fetchFallaRetornaNull() {
        Auditable auditable = mockAuditable(OperationType.UPDATE);
        throwOnFetchCurrentState = true;

        Map<String, Object> result = aspect.testCaptureBeforeData(auditable, new Object[] { "ID-1" });

        assertNull(result);
    }

    @Test
    @DisplayName("buildDataObject - CREATE debe construir entity desde result")
    void buildDataObject_create() {
        Map<String, Object> resultEntity = Map.of(
                "id", "ID-1",
                "name", "Docente");

        Map<String, Object> data = aspect.testBuildDataObject(
                OperationType.CREATE,
                new Object[] {},
                resultEntity,
                null);

        assertTrue(data.containsKey("entity"));
        assertEquals(resultEntity, data.get("entity"));
    }

    @Test
    @DisplayName("buildDataObject - CREATE con result null retorna data vacío")
    void buildDataObject_createResultNull() {
        Map<String, Object> data = aspect.testBuildDataObject(
                OperationType.CREATE,
                new Object[] {},
                null,
                null);

        assertTrue(data.isEmpty());
    }

    @Test
    @DisplayName("buildDataObject - UPDATE debe construir changes")
    void buildDataObject_update() {
        Map<String, Object> before = Map.of(
                "name", "Docente",
                "description", "Anterior");

        Map<String, Object> after = Map.of(
                "name", "Director",
                "description", "Anterior");

        Map<String, Object> data = aspect.testBuildDataObject(
                OperationType.UPDATE,
                new Object[] { "ID-1" },
                after,
                before);

        assertTrue(data.containsKey("changes"));

        Map<?, ?> changes = (Map<?, ?>) data.get("changes");
        assertEquals(1, changes.size());
        assertTrue(changes.containsKey("name"));
    }

    @Test
    @DisplayName("buildDataObject - UPDATE debe incluir context cuando exista")
    void buildDataObject_updateConContext() {
        aspect.enableContext = true;

        Map<String, Object> before = Map.of(
                "email", "user@unicauca.edu.co",
                "name", "Docente");

        Map<String, Object> after = Map.of(
                "email", "updated@unicauca.edu.co",
                "name", "Docente");

        Map<String, Object> data = aspect.testBuildDataObject(
                OperationType.UPDATE,
                new Object[] { "ID-1" },
                after,
                before);

        assertTrue(data.containsKey("context"));

        Map<?, ?> context = (Map<?, ?>) data.get("context");
        assertEquals("user@unicauca.edu.co", context.get("email"));
    }

    @Test
    @DisplayName("buildDataObject - DELETE debe usar beforeData como entity")
    void buildDataObject_deleteConBeforeData() {
        Map<String, Object> before = Map.of(
                "id", "ID-1",
                "name", "Docente");

        Map<String, Object> data = aspect.testBuildDataObject(
                OperationType.DELETE,
                new Object[] { "ID-1" },
                null,
                before);

        assertEquals(before, data.get("entity"));
    }

    @Test
    @DisplayName("buildDataObject - DELETE sin beforeData debe usar id de args")
    void buildDataObject_deleteSinBeforeData() {
        Map<String, Object> data = aspect.testBuildDataObject(
                OperationType.DELETE,
                new Object[] { "ID-1" },
                null,
                null);

        assertEquals(Map.of("id", "ID-1"), data.get("entity"));
    }

    @Test
    @DisplayName("buildDataObject - operación especial debe usar buildSpecialDataObject")
    void buildDataObject_operacionEspecial() {
        specialDataObject = Map.of(
                "roleName", "auditor",
                "permissions", List.of("Editar Impuestos"));

        Map<String, Object> data = aspect.testBuildDataObject(
                OperationType.ASSIGN_PERMISSIONS,
                new Object[] { List.of("Editar Impuestos"), "auditor" },
                true,
                null);

        assertEquals(specialDataObject, data);
    }

    @Test
    @DisplayName("executeAudit - CREATE debe publicar evento")
    void executeAudit_createPublicaEvento() throws Throwable {
        Auditable auditable = mockAuditable(OperationType.CREATE);

        Map<String, Object> result = Map.of(
                "id", "ID-1",
                "name", "Docente");

        when(joinPoint.getArgs()).thenReturn(new Object[] {});
        when(joinPoint.proceed()).thenReturn(result);
        when(auditEventBuilder.build(eq(auditable), eq(OperationType.CREATE), eq("ID-1"), anyMap()))
                .thenReturn(operationEventDto);

        Object response = aspect.executeAudit(joinPoint, auditable);

        assertEquals(result, response);
        verify(auditEventPublisher).publish(operationEventDto);
    }

    @Test
    @DisplayName("executeAudit - UPDATE sin cambios no debe publicar evento")
    void executeAudit_updateSinCambiosNoPublica() throws Throwable {
        Auditable auditable = mockAuditable(OperationType.UPDATE);

        stubbedCurrentState = Map.of("name", "Docente");

        Map<String, Object> result = Map.of("name", "Docente");

        when(joinPoint.getArgs()).thenReturn(new Object[] { "ID-1" });
        when(joinPoint.proceed()).thenReturn(result);

        Object response = aspect.executeAudit(joinPoint, auditable);

        assertEquals(result, response);
        verifyNoInteractions(auditEventBuilder);
        verifyNoInteractions(auditEventPublisher);
    }

    @Test
    @DisplayName("executeAudit - UPDATE con cambios debe publicar evento")
    void executeAudit_updateConCambiosPublica() throws Throwable {
        Auditable auditable = mockAuditable(OperationType.UPDATE);

        stubbedCurrentState = Map.of("name", "Docente");

        Map<String, Object> result = Map.of("name", "Director");

        when(joinPoint.getArgs()).thenReturn(new Object[] { "ID-1" });
        when(joinPoint.proceed()).thenReturn(result);
        when(auditEventBuilder.build(eq(auditable), eq(OperationType.UPDATE), eq("ID-1"), anyMap()))
                .thenReturn(operationEventDto);

        Object response = aspect.executeAudit(joinPoint, auditable);

        assertEquals(result, response);
        verify(auditEventPublisher).publish(operationEventDto);
    }

    @Test
    @DisplayName("executeAudit - DELETE debe publicar evento")
    void executeAudit_deletePublica() throws Throwable {
        Auditable auditable = mockAuditable(OperationType.DELETE);

        stubbedCurrentState = Map.of(
                "id", "ID-1",
                "name", "Docente");

        when(joinPoint.getArgs()).thenReturn(new Object[] { "ID-1" });
        when(joinPoint.proceed()).thenReturn(null);
        when(auditEventBuilder.build(eq(auditable), eq(OperationType.DELETE), eq("ID-1"), anyMap()))
                .thenReturn(operationEventDto);

        Object response = aspect.executeAudit(joinPoint, auditable);

        assertNull(response);
        verify(auditEventPublisher).publish(operationEventDto);
    }

    @Test
    @DisplayName("executeAudit - si buildDataObject falla no debe romper operación original")
    void executeAudit_errorConstruyendoAuditoriaNoRompeOperacion() throws Throwable {
        Auditable auditable = mockAuditable(OperationType.CREATE);

        throwOnBuildDataObject = true;

        Map<String, Object> result = Map.of("id", "ID-1");

        when(joinPoint.getArgs()).thenReturn(new Object[] {});
        when(joinPoint.proceed()).thenReturn(result);

        Object response = aspect.executeAudit(joinPoint, auditable);

        assertEquals(result, response);
        verifyNoInteractions(auditEventPublisher);
    }

    @Test
    @DisplayName("executeAudit - si proceed lanza excepción no debe publicar evento")
    void executeAudit_proceedLanzaExcepcion() throws Throwable {
        Auditable auditable = mockAuditable(OperationType.UPDATE);

        stubbedCurrentState = Map.of("name", "Docente");

        when(joinPoint.getArgs()).thenReturn(new Object[] { "ID-1" });
        when(joinPoint.proceed()).thenThrow(new RuntimeException("Error negocio"));

        RuntimeException ex = assertThrows(RuntimeException.class,
                () -> aspect.executeAudit(joinPoint, auditable));

        assertEquals("Error negocio", ex.getMessage());
        verifyNoInteractions(auditEventBuilder);
        verifyNoInteractions(auditEventPublisher);
    }

    private Auditable mockAuditable(OperationType type) {
        Auditable auditable = mock(Auditable.class);

        lenient().when(auditable.operationType()).thenReturn(type);
        lenient().when(auditable.affectedTable()).thenReturn("PROFILE");
        lenient().when(auditable.moduleName()).thenReturn("CONFIGURATION");

        return auditable;
    }

    private class TestableBaseAuditAspect extends BaseAuditAspect {

        private boolean enableContext = false;

        protected TestableBaseAuditAspect(
                AuditEventBuilder auditEventBuilder,
                AuditEventPublisher auditEventPublisher) {
            super(auditEventBuilder, auditEventPublisher);
        }

        @Override
        protected Map<String, Object> fetchCurrentState(Auditable auditable, Object[] args) {
            if (throwOnFetchCurrentState) {
                throw new RuntimeException("Keycloak caído");
            }

            return stubbedCurrentState;
        }

        @Override
        @SuppressWarnings("unchecked")
        protected Map<String, Object> entityToMap(Object object) {
            if (stubbedEntityMap != null) {
                return stubbedEntityMap;
            }

            if (object instanceof Map<?, ?> map) {
                return (Map<String, Object>) map;
            }

            return Map.of();
        }

        @Override
        protected String resolveRegisterId(
                Auditable auditable,
                Object[] args,
                Object result,
                Map<String, Object> beforeData) {
            return "ID-1";
        }

        @Override
        protected Map<String, Object> buildContext(Map<String, Object> data) {
            if (!enableContext || data == null || data.isEmpty()) {
                return Map.of();
            }

            Map<String, Object> context = new LinkedHashMap<>();

            if (data.get("email") != null) {
                context.put("email", data.get("email"));
            }

            return context;
        }

        @Override
        protected Map<String, Object> buildSpecialDataObject(
                OperationType operationType,
                Object[] args,
                Object result,
                Map<String, Object> beforeData) {
            return specialDataObject;
        }

        @Override
        protected Map<String, Object> buildDataObject(
                OperationType operationType,
                Object[] args,
                Object result,
                Map<String, Object> beforeData) {

            if (throwOnBuildDataObject) {
                throw new RuntimeException("Error armando dataObject");
            }

            return super.buildDataObject(operationType, args, result, beforeData);
        }

        Map<String, Object> testBuildDiff(
                Map<String, Object> before,
                Map<String, Object> after) {
            return buildDiff(before, after);
        }

        Map<String, Object> testCaptureBeforeData(
                Auditable auditable,
                Object[] args) {
            return captureBeforeData(auditable, args);
        }

        Map<String, Object> testBuildDataObject(
                OperationType operationType,
                Object[] args,
                Object result,
                Map<String, Object> beforeData) {
            return buildDataObject(operationType, args, result, beforeData);
        }
    }

}
