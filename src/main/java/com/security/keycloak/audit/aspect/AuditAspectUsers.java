package com.security.keycloak.audit.aspect;

import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;

import com.security.keycloak.audit.annotation.Auditable;
import com.security.keycloak.audit.builder.AuditEventBuilder;
import com.security.keycloak.audit.publisher.AuditEventPublisher;
import com.security.keycloak.dtos.UserDTO;
import com.security.keycloak.service.IUserKeycloakService;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Aspecto de auditoría para operaciones de gestión de usuarios.
 * <p>
 * Intercepta los métodos del servicio {@code UserKeycloakServiceImpl} anotados
 * con {@link Auditable} y publica el evento correspondiente al exchange de
 * auditoría.
 * </p>
 * <p>
 * El campo {@code password} nunca se incluye en el {@code dataObject},
 * independientemente
 * de si viene informado en el DTO de entrada.
 * </p>
 */
@Aspect
@Component
@Slf4j
public class AuditAspectUsers extends BaseAuditAspect {

    @Lazy
    private final IUserKeycloakService userKeycloakService;

    private static final Set<String> TECHNICAL_ROLES = Set.of(
            "offline_access",
            "uma_authorization");

    public AuditAspectUsers(AuditEventBuilder auditEventBuilder,
            AuditEventPublisher auditEventPublisher,
            @Lazy IUserKeycloakService userKeycloakService) {
        super(auditEventBuilder, auditEventPublisher);
        this.userKeycloakService = userKeycloakService;
    }

    /**
     * Punto de corte: intercepta cualquier método anotado con {@link Auditable}
     * dentro del paquete de servicios de usuarios.
     *
     * @param joinPoint punto de unión.
     * @param auditable metadatos de la anotación.
     * @return resultado original del método interceptado.
     * @throws Throwable si el método lanza una excepción.
     */
    @Around("@annotation(auditable) && within(com.security.keycloak.service.impl.UserKeycloakServiceImpl)")
    public Object audit(ProceedingJoinPoint joinPoint, Auditable auditable) throws Throwable {
        return executeAudit(joinPoint, auditable);
    }

    /**
     * Obtiene el estado actual del usuario en Keycloak antes de que la operación
     * lo modifique. Se usa para UPDATE y DELETE.
     *
     * @param auditable metadatos de la anotación.
     * @param args      argumentos del método; {@code args[0]} es el {@code userId}.
     * @return mapa con el estado previo del usuario, o {@code null} si no se
     *         encuentra.
     */
    @Override
    protected Map<String, Object> fetchCurrentState(Auditable auditable, Object[] args) {
        try {
            String userId = (String) args[0];
            UserDTO user = userKeycloakService.findUserById(userId);
            return entityToMap(user);
        } catch (Exception e) {
            log.warn("No se pudo obtener estado previo del usuario: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Serializa un {@link UserDTO} a un mapa plano.
     * El campo {@code password} se excluye siempre por seguridad.
     *
     * @param object instancia de {@link UserDTO}.
     * @return mapa con los campos del usuario sin datos sensibles,
     *         o {@code null} si el objeto no es del tipo esperado.
     */
    @Override
    protected Map<String, Object> entityToMap(Object object) {
        if (!(object instanceof UserDTO user)) {
            return Map.of();
        }

        List<String> cleanRoles = user.getRoles() == null ? List.of()
                : user.getRoles().stream()
                        .filter(Objects::nonNull)
                        .filter(role -> !TECHNICAL_ROLES.contains(role))
                        .filter(role -> !role.startsWith("default-roles-"))
                        .distinct()
                        .sorted()
                        .toList();

        Map<String, Object> map = new LinkedHashMap<>();
        map.put("email", user.getEmail());
        map.put("firstName", user.getFirstName());
        map.put("lastName", user.getLastName());
        map.put("roles", cleanRoles);
        map.entrySet().removeIf(entry -> entry.getValue() == null);
        return map;
    }

    @Override
    protected Map<String, Object> buildContext(Map<String, Object> data) {
        if (data == null) {
            return Map.of();
        }
        Map<String, Object> context = new LinkedHashMap<>();
        if (data.get("email") != null) {
            context.put("email", data.get("email"));
        }
        return context;
    }

    /**
     * Resuelve el identificador del registro afectado.
     * Para CREATE se obtiene del {@link UserDTO} retornado;
     * para UPDATE y DELETE se toma de {@code args[0]}.
     *
     * @param auditable  metadatos de la anotación.
     * @param args       argumentos del método.
     * @param result     resultado del método (UserDTO en CREATE/UPDATE).
     * @param beforeData estado previo (contiene {@code id} en UPDATE/DELETE).
     * @return identificador del usuario afectado.
     */
    @Override
    protected String resolveRegisterId(Auditable auditable, Object[] args,
            Object result, Map<String, Object> beforeData) {
        return switch (auditable.operationType()) {
            case CREATE -> result instanceof UserDTO u ? u.getId() : "UNKNOWN";
            case UPDATE, DELETE -> (String) args[0];
            default -> "UNKNOWN";
        };
    }
}
