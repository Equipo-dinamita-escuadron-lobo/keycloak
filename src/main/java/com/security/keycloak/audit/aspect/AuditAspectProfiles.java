package com.security.keycloak.audit.aspect;

import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;

import com.security.keycloak.audit.annotation.Auditable;
import com.security.keycloak.audit.annotation.OperationType;
import com.security.keycloak.audit.builder.AuditEventBuilder;
import com.security.keycloak.audit.publisher.AuditEventPublisher;
import com.security.keycloak.dtos.ProfileDTO;
import com.security.keycloak.service.IProfileKeycloakService;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Aspecto de auditoría para operaciones de gestión de perfiles (roles de
 * Keycloak).
 * <p>
 * Los perfiles se mapean a roles de realm en Keycloak. El {@code registerId}
 * corresponde al ID interno del rol.
 * </p>
 */
@Aspect
@Component
@Slf4j
public class AuditAspectProfiles extends BaseAuditAspect {

    @Lazy
    private final IProfileKeycloakService profileKeycloakService;

    public AuditAspectProfiles(AuditEventBuilder auditEventBuilder,
            AuditEventPublisher auditEventPublisher,
            @Lazy IProfileKeycloakService profileKeycloakService) {
        super(auditEventBuilder, auditEventPublisher);
        this.profileKeycloakService = profileKeycloakService;
    }

    /**
     * Punto de corte: intercepta métodos anotados con {@link Auditable}
     * dentro del servicio de perfiles.
     */
    @Around("@annotation(auditable) && within(com.security.keycloak.service.impl.ProfileKeycloakServiceImpl)")
    public Object audit(ProceedingJoinPoint joinPoint, Auditable auditable) throws Throwable {
        return executeAudit(joinPoint, auditable);
    }

    /**
     * Obtiene el estado actual del perfil en Keycloak.
     * {@code args[0]} es el {@code profileId} en UPDATE y DELETE.
     */
    @Override
    protected Map<String, Object> fetchCurrentState(Auditable auditable, Object[] args) {
        if (auditable.operationType() == OperationType.CREATE) {
            return Map.of();
        }
        try {
            String profileId = (String) args[0];
            ProfileDTO profile = profileKeycloakService.findProfileById(profileId);
            return entityToMap(profile);
        } catch (Exception e) {
            log.warn("No se pudo obtener estado previo del perfil: {}", e.getMessage());
            return Map.of();
        }
    }

    /**
     * Serializa un {@link ProfileDTO} a un mapa plano.
     *
     * @param object instancia de {@link ProfileDTO}.
     * @return mapa con id, name y description, o {@code null} si el tipo no
     *         coincide.
     */
    @Override
    protected Map<String, Object> entityToMap(Object object) {
        if (!(object instanceof ProfileDTO profile)) {
            return Map.of();
        }
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("name", profile.getName());
        map.put("description", profile.getDescription());
        map.entrySet().removeIf(entry -> entry.getValue() == null);
        return map;
    }

    @Override
    protected Map<String, Object> buildContext(Map<String, Object> data) {
        if (data == null || data.isEmpty()) {
            return Map.of();
        }
        Map<String, Object> context = new LinkedHashMap<>();
        if (data.get("name") != null) {
            context.put("profileName", data.get("name"));
        }
        return context;
    }

    /**
     * Resuelve el identificador del perfil afectado.
     * En CREATE se toma del {@link ProfileDTO} retornado;
     * en UPDATE y DELETE de {@code args[0]}.
     */
    @Override
    protected String resolveRegisterId(Auditable auditable, Object[] args,
            Object result, Map<String, Object> beforeData) {

        return switch (auditable.operationType()) {
            case CREATE -> result instanceof ProfileDTO profile
                    ? profile.getId()
                    : "UNKNOWN";
            case UPDATE, DELETE -> args != null && args.length > 0 && args[0] instanceof String profileId
                    ? profileId
                    : "UNKNOWN";
            default -> "UNKNOWN";
        };
    }
}
