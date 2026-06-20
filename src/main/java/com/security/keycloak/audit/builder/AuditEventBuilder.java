package com.security.keycloak.audit.builder;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import com.security.keycloak.audit.annotation.Auditable;
import com.security.keycloak.audit.annotation.OperationType;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Construye el {@link OperationEventDto} con los datos del usuario autenticado
 * extraídos del {@code SecurityContextHolder}.
 * <p>
 * Cuando el contexto de seguridad está vacío (endpoints públicos como
 * {@code /register} o {@code /reset-password}), los campos de identidad
 * se dejan en {@code "SYSTEM"} para no bloquear el flujo de negocio.
 * </p>
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AuditEventBuilder {

    /**
     * Construye el DTO de auditoría combinando metadatos de la anotación
     * con la identidad del usuario autenticado en el contexto actual.
     *
     * @param auditable     metadatos de la anotación {@link Auditable}.
     * @param operationType tipo de operación resuelto (puede diferir del
     *                      declarado).
     * @param registerId    identificador del registro afectado.
     * @param dataObject    mapa con el detalle del cambio (before/after, entidad,
     *                      etc.).
     * @return DTO listo para publicar.
     */
    public OperationEventDto build(
            Auditable auditable,
            OperationType operationType,
            String registerId,
            Map<String, Object> dataObject) {

        String userId = "SYSTEM";
        String userName = "SYSTEM";
        List<String> roles = Collections.emptyList();

        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
                userId = jwt.getSubject();
                userName = jwt.getClaimAsString("preferred_username");
                if (userName == null) {
                    userName = jwt.getClaimAsString("email");
                }
                roles = extractRoles(jwt);
            }
        } catch (Exception e) {
            log.warn("No se pudo extraer identidad del contexto de seguridad: {}", e.getMessage());
        }

        return OperationEventDto.builder()
                .enterpriseId("SYSTEM")
                .userId(userId)
                .userName(userName)
                .userRole(roles)
                .operationType(operationType.name())
                .operationAt(Instant.now())
                .moduleName(auditable.moduleName())
                .affectedTable(auditable.affectedTable())
                .registerId(registerId)
                .dataObject(dataObject)
                .build();
    }

    private static final Set<String> SYSTEM_ROLES = Set.of(
            "offline_access",
            "uma_authorization",
            "default-roles-oauth2-realm");

    /**
     * Extrae los roles de realm del JWT filtrando los roles internos de Keycloak
     * que no tienen relevancia para la auditoría.
     *
     * @param jwt token JWT del usuario autenticado.
     * @return lista de roles de negocio del usuario.
     */
    private List<String> extractRoles(Jwt jwt) {
        try {
            Map<String, Object> realmAccess = jwt.getClaim("realm_access");
            if (realmAccess == null)
                return Collections.emptyList();
            Object rolesObj = realmAccess.get("roles");
            if (!(rolesObj instanceof List<?> rolesList))
                return Collections.emptyList();
            return rolesList.stream()
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .filter(r -> !SYSTEM_ROLES.contains(r))
                    .toList();
        } catch (Exception e) {
            log.warn("No se pudieron extraer roles del JWT: {}", e.getMessage());
            return Collections.emptyList();
        }
    }
}
