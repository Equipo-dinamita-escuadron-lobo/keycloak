package com.security.keycloak.audit.aspect;

import lombok.extern.slf4j.Slf4j;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

import org.aspectj.lang.ProceedingJoinPoint;
import com.security.keycloak.audit.annotation.Auditable;
import com.security.keycloak.audit.annotation.OperationType;
import com.security.keycloak.audit.builder.AuditEventBuilder;
import com.security.keycloak.audit.builder.OperationEventDto;
import com.security.keycloak.audit.publisher.AuditEventPublisher;

/**
 * Clase base para todos los aspectos de auditoría del micro de Keycloak.
 * <p>
 * Implementa el flujo general: capturar estado previo → ejecutar el método
 * → construir el {@code dataObject} → publicar el evento. Cada aspecto concreto
 * solo necesita implementar cómo obtener el estado actual desde Keycloak,
 * cómo serializar la entidad a mapa y cómo resolver el {@code registerId}.
 * </p>
 * <p>
 * A diferencia de {@code accountCatalogue}, aquí no hay repositorio propio:
 * el {@code fetchCurrentState} consulta directamente la API de Keycloak
 * a través del servicio correspondiente.
 * </p>
 */
@Slf4j
public abstract class BaseAuditAspect {

    protected final AuditEventBuilder auditEventBuilder;
    protected final AuditEventPublisher auditEventPublisher;

    protected BaseAuditAspect(AuditEventBuilder auditEventBuilder, AuditEventPublisher auditEventPublisher) {
        this.auditEventBuilder = auditEventBuilder;
        this.auditEventPublisher = auditEventPublisher;
    }

    /**
     * Obtiene el estado actual de la entidad desde Keycloak antes de que
     * el método anotado lo modifique. Solo se invoca para UPDATE y DELETE.
     *
     * @param auditable metadatos de la anotación.
     * @param args      argumentos del método interceptado.
     * @return mapa con el estado previo de la entidad, o {@code null} si no aplica.
     */
    protected abstract Map<String, Object> fetchCurrentState(Auditable auditable, Object[] args);

    /**
     * Convierte una entidad de dominio (UserDTO, ProfileDTO, etc.) a un mapa
     * plano de clave-valor apto para incluir en el {@code dataObject}.
     * La contraseña nunca debe incluirse en este mapa.
     *
     * @param object entidad a serializar.
     * @return mapa con los campos de la entidad, sin campos sensibles.
     */
    protected abstract Map<String, Object> entityToMap(Object object);

    /**
     * Resuelve el identificador del registro afectado por la operación.
     * Para CREATE se obtiene del resultado; para UPDATE y DELETE, de los args.
     *
     * @param auditable  metadatos de la anotación.
     * @param args       argumentos del método interceptado.
     * @param result     resultado del método (puede ser null en DELETE).
     * @param beforeData estado previo capturado antes de la operación.
     * @return identificador del registro como String.
     */
    protected abstract String resolveRegisterId(Auditable auditable, Object[] args,
            Object result, Map<String, Object> beforeData);

    /**
     * Punto de entrada del flujo de auditoría. Captura el estado previo,
     * ejecuta el método interceptado y publica el evento si la operación
     * produce cambios auditables.
     *
     * @param joinPoint punto de unión del aspecto.
     * @param auditable metadatos de la anotación presente en el método.
     * @return el resultado original del método interceptado.
     * @throws Throwable si el método interceptado lanza una excepción.
     */
    public Object executeAudit(ProceedingJoinPoint joinPoint, Auditable auditable) throws Throwable {
        Object[] args = joinPoint.getArgs();
        Map<String, Object> beforeData = captureBeforeData(auditable, args);

        Object result = joinPoint.proceed();

        try {
            Map<String, Object> dataObject = buildDataObject(auditable.operationType(), args, result, beforeData);

            if (dataObject == null || dataObject.isEmpty())
                return result;
            if (dataObject.containsKey("changes")) {
                Map<?, ?> changes = (Map<?, ?>) dataObject.get("changes");
                if (changes == null || changes.isEmpty())
                    return result;
            }

            String registerId = resolveRegisterId(auditable, args, result, beforeData);
            OperationEventDto dto = auditEventBuilder.build(auditable, auditable.operationType(), registerId,
                    dataObject);
            auditEventPublisher.publish(dto);
        } catch (Exception e) {
            log.error("Error construyendo evento de auditoría [{}]: {}", auditable.operationType(), e.getMessage(), e);
        }

        return result;
    }

    /**
     * Captura el estado previo de la entidad solo cuando la operación lo requiere.
     *
     * @param auditable metadatos de la anotación.
     * @param args      argumentos del método.
     * @return mapa con el estado anterior, o {@code null} si la operación es
     *         CREATE.
     */
    protected Map<String, Object> captureBeforeData(Auditable auditable, Object[] args) {
        try {
            return switch (auditable.operationType()) {
                case UPDATE, DELETE -> fetchCurrentState(auditable, args);
                default -> null;
            };
        } catch (Exception e) {
            log.warn("No se pudo capturar estado before para {}: {}",
                    auditable.operationType(), e.getMessage());
            return null;
        }
    }

    protected Map<String, Object> buildContext(Map<String, Object> data) {
        return Map.of();
    }

    /**
     * Construye el {@code dataObject} que se incluirá en el evento de auditoría.
     * El contenido varía según el tipo de operación:
     * <ul>
     * <li>CREATE: la entidad creada.</li>
     * <li>UPDATE: el diff entre estado previo y posterior.</li>
     * <li>DELETE: la entidad eliminada (estado previo).</li>
     * <li>ASSIGN_PERMISSIONS / UPDATE_PERMISSIONS / RESET_PASSWORD: datos
     * específicos
     * construidos por el aspecto concreto vía {@link #buildSpecialDataObject}.</li>
     * </ul>
     *
     * @param operationType tipo de operación.
     * @param args          argumentos del método interceptado.
     * @param result        resultado del método.
     * @param beforeData    estado previo capturado antes de la ejecución.
     * @return mapa con el detalle del cambio.
     */
    protected Map<String, Object> buildDataObject(OperationType operationType, Object[] args, Object result,
            Map<String, Object> beforeData) {
        return switch (operationType) {
            case CREATE -> {
                Map<String, Object> specialData = buildSpecialDataObject(operationType, args, result, beforeData);

                if (specialData != null && !specialData.isEmpty()) {
                    Map<String, Object> data = new LinkedHashMap<>();
                    data.put("entity", specialData);
                    yield data;
                }

                Map<String, Object> data = new LinkedHashMap<>();
                if (result != null) {
                    data.put("entity", entityToMap(result));
                }
                yield data;
            }
            case UPDATE -> {
                Map<String, Object> afterData = entityToMap(result);
                Map<String, Object> diff = buildDiff(beforeData, afterData);

                Map<String, Object> data = new LinkedHashMap<>();
                Map<String, Object> context = buildContext(beforeData);
                if (!context.isEmpty()) {
                    data.put("context", context);
                }
                data.put("changes", diff);
                yield data;
            }
            case DELETE -> {
                Map<String, Object> data = new LinkedHashMap<>();
                data.put("entity", beforeData != null ? beforeData : Map.of("id", args[0]));
                yield data;
            }
            default -> buildSpecialDataObject(operationType, args, result, beforeData);
        };
    }

    /**
     * Hook que los aspectos concretos pueden sobreescribir para manejar
     * operaciones no estándar como ASSIGN_PERMISSIONS, UPDATE_PERMISSIONS
     * o RESET_PASSWORD. Por defecto retorna un mapa vacío.
     *
     * @param operationType tipo de operación especial.
     * @param args          argumentos del método interceptado.
     * @param result        resultado del método.
     * @param beforeData    estado previo (puede ser null).
     * @return mapa con el detalle de la operación especial.
     */
    protected Map<String, Object> buildSpecialDataObject(OperationType operationType, Object[] args, Object result,
            Map<String, Object> beforeData) {
        return Map.of();
    }

    /**
     * Computa la diferencia campo a campo entre dos mapas de estado.
     * Solo incluye campos cuyo valor cambió entre {@code before} y {@code after}.
     *
     * @param before estado anterior.
     * @param after  estado posterior.
     * @return mapa con las diferencias, en formato
     *         {@code {campo: {before: x, after: y}}}.
     */
    protected Map<String, Object> buildDiff(Map<String, Object> before, Map<String, Object> after) {
        Map<String, Object> diff = new LinkedHashMap<>();
        if (before == null || after == null) {
            return diff;
        }
        after.forEach((key, afterValue) -> {
            Object beforeValue = before.get(key);
            if (!Objects.equals(beforeValue, afterValue)) {
                Map<String, Object> change = new LinkedHashMap<>();
                change.put("before", beforeValue);
                change.put("after", afterValue);
                diff.put(key, change);
            }
        });
        return diff;
    }
}
