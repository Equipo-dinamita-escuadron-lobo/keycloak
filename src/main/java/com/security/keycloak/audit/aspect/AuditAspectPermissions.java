package com.security.keycloak.audit.aspect;

import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;

import com.security.keycloak.audit.annotation.Auditable;
import com.security.keycloak.audit.annotation.OperationType;
import com.security.keycloak.audit.builder.AuditEventBuilder;
import com.security.keycloak.audit.publisher.AuditEventPublisher;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Aspecto de auditoría para operaciones de gestión de permisos.
 * <p>
 * Las operaciones de permisos no son CRUD clásico: no hay una entidad única
 * que se crea o elimina, sino asociaciones entre roles y permisos que cambian.
 * Por eso se usan los tipos {@code ASSIGN_PERMISSIONS} y
 * {@code UPDATE_PERMISSIONS},
 * y el {@code dataObject} describe qué permisos se asociaron o qué cambios se
 * hicieron.
 * </p>
 * <p>
 * No se necesita {@code fetchCurrentState} porque el servicio ya calcula
 * internamente los permisos a agregar y quitar ({@code toAdd} /
 * {@code toRemove}).
 * El {@code dataObject} refleja la intención declarada en el request.
 * </p>
 */
@Aspect
@Component
@Slf4j
public class AuditAspectPermissions extends BaseAuditAspect {

    public AuditAspectPermissions(AuditEventBuilder auditEventBuilder,
            AuditEventPublisher auditEventPublisher) {
        super(auditEventBuilder, auditEventPublisher);
    }

    @Around("@annotation(auditable) && within(com.security.keycloak.service.impl.PermissionKeycloakServiceImpl)")
    public Object audit(ProceedingJoinPoint joinPoint, Auditable auditable) throws Throwable {
        return executeAudit(joinPoint, auditable);
    }

    @Override
    protected Map<String, Object> fetchCurrentState(Auditable auditable, Object[] args) {
        return Map.of();
    }

    @Override
    protected Map<String, Object> entityToMap(Object object) {
        return Map.of();
    }

    @Override
    protected String resolveRegisterId(Auditable auditable, Object[] args,
            Object result, Map<String, Object> beforeData) {

        return args != null && args.length > 1 && args[1] instanceof String roleName
                ? roleName
                : "UNKNOWN";
    }

    @Override
    @SuppressWarnings("unchecked")
    protected Map<String, Object> buildSpecialDataObject(OperationType operationType,
            Object[] args,
            Object result,
            Map<String, Object> beforeData) {

        List<String> permissions = args != null && args.length > 0 && args[0] instanceof List<?>
                ? ((List<String>) args[0])
                : List.of();

        String roleName = args != null && args.length > 1 && args[1] instanceof String
                ? (String) args[1]
                : "UNKNOWN";

        Map<String, Object> entity = new LinkedHashMap<>();
        entity.put("roleName", roleName);
        entity.put("permissions", permissions);

        return entity;
    }
}
