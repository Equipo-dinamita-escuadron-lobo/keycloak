package com.security.keycloak.service.impl;

import java.util.Arrays;
import java.util.List;

import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.RoleResource;
import org.keycloak.admin.client.resource.RolesResource;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.stereotype.Service;

import com.security.keycloak.audit.annotation.Auditable;
import com.security.keycloak.audit.annotation.OperationType;
import com.security.keycloak.controller.exception.ConflictException;
import com.security.keycloak.controller.exception.ResourceNotFoundException;
import com.security.keycloak.dtos.ProfileDTO;
import com.security.keycloak.service.IPermissionKeycloakService;
import com.security.keycloak.service.IProfileKeycloakService;
import com.security.keycloak.util.KeycloakProvider;

import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.NotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Implementación del servicio de gestión de perfiles en Keycloak.
 * <p>
 * Proporciona operaciones para crear, buscar, actualizar y eliminar perfiles
 * (roles)
 * dentro de un realm de Keycloak, aplicando reglas de negocio y manejo de
 * excepciones.
 * </p>
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class ProfileKeycloakServiceImpl implements IProfileKeycloakService {

    private final KeycloakProvider keycloakProvider;
    private final IPermissionKeycloakService permissionKeycloakService;

    /**
     * Obtiene todos los perfiles (roles) disponibles en Keycloak,
     * excluyendo los roles predeterminados del sistema.
     *
     * @return lista de perfiles como {@link ProfileDTO}.
     */
    @Override
    public List<ProfileDTO> findAllProfiles() {
        List<String> excludedRoles = Arrays.asList(
                "uma_authorization",
                "offline_access",
                "default-roles-spring-boot-realm-dev",
                "default-roles-oauth2-realm");

        return keycloakProvider.getRealmResource()
                .roles()
                .list()
                .stream()
                .filter(role -> !excludedRoles.contains(role.getName()))
                .map(role -> ProfileDTO.builder()
                        .id(role.getId())
                        .name(role.getName())
                        .description(role.getDescription())
                        .build())
                .toList();
    }

    /**
     * Busca un perfil en Keycloak por su identificador.
     *
     * @param profileId identificador del perfil.
     * @return el perfil encontrado como {@link ProfileDTO}.
     * @throws ResourceNotFoundException si no existe un perfil con ese ID.
     */
    @Override
    public ProfileDTO findProfileById(String profileId) {
        return keycloakProvider.getRealmResource()
                .roles()
                .list()
                .stream()
                .filter(role -> role.getId().equals(profileId))
                .map(role -> ProfileDTO.builder()
                        .id(role.getId())
                        .name(role.getName())
                        .description(role.getDescription())
                        .build())
                .findFirst()
                .orElseThrow(() -> new ResourceNotFoundException("No se encontró el perfil con ID " + profileId));
    }

    /**
     * Crea un nuevo perfil en Keycloak.
     * <p>
     * Verifica previamente que no exista otro perfil con el mismo nombre.
     * </p>
     *
     * @param profileDTO datos del perfil a crear.
     * @return el perfil creado como {@link ProfileDTO}.
     * @throws ConflictException         si ya existe un perfil con el mismo nombre.
     * @throws ResourceNotFoundException si el recurso de Keycloak no se encuentra.
     */
    @Override
    @Auditable(operationType = OperationType.CREATE, affectedTable = "PROFILE")
    public ProfileDTO createProfile(ProfileDTO profileDTO) {
        RealmResource realm = keycloakProvider.getRealmResource();
        RolesResource roles = realm.roles();
        String roleName = profileDTO.getName();

        try {
            roles.get(roleName).toRepresentation();
            log.error("El nombre de perfil '{}' ya existe", roleName);
            throw new ConflictException("El nombre del perfil ya existe");
        } catch (NotFoundException notExists) {
        }

        RoleRepresentation rep = new RoleRepresentation();
        rep.setName(roleName);
        rep.setDescription(profileDTO.getDescription());

        try {
            roles.create(rep);
            RoleRepresentation created = roles.get(roleName).toRepresentation();
            log.info("Perfil '{}' creado correctamente (id={})", roleName, created.getId());
            return ProfileDTO.builder()
                    .id(created.getId())
                    .name(created.getName())
                    .description(created.getDescription())
                    .build();
        } catch (ClientErrorException cee) {
            int status = cee.getResponse() != null ? cee.getResponse().getStatus() : 500;
            log.error("Error de Keycloak al crear perfil ({}). Status={} - {}", roleName, status, cee.getMessage(),
                    cee);
            if (status == 409)
                throw new ConflictException("El nombre del perfil ya existe");
            if (status == 404)
                throw new ResourceNotFoundException("Recurso de Keycloak no encontrado");
            throw new RuntimeException("Error de Keycloak (" + status + "): " + cee.getMessage(), cee);
        }
    }

    /**
     * Elimina un perfil de Keycloak.
     * <p>
     * Verifica que el perfil no esté asignado a ningún usuario antes de eliminarlo.
     * </p>
     *
     * @param profileId identificador del perfil a eliminar.
     * @throws ConflictException         si el perfil está asignado a usuarios.
     * @throws ResourceNotFoundException si el perfil no existe.
     */
    @Override
    @Auditable(operationType = OperationType.DELETE, affectedTable = "PROFILE")
    public void deleteProfile(String profileId) {
        RealmResource realm = keycloakProvider.getRealmResource();

        RoleRepresentation roleToDelete = realm.roles().list().stream()
                .filter(role -> profileId.equals(role.getId()))
                .findFirst()
                .orElseThrow(() -> new ResourceNotFoundException("No se encontró el perfil con ID " + profileId));

        String roleName = roleToDelete.getName();
        RoleResource roleResource = realm.roles().get(roleName);

        List<UserRepresentation> users = roleResource.getUserMembers();
        if (users != null && !users.isEmpty()) {
            throw new ConflictException("El perfil está asignado a uno o más usuarios");
        }

        try {
            permissionKeycloakService.detachPolicyReferencesForRole(roleName);
        } catch (ConflictException | ResourceNotFoundException e) {
            throw e; // mantén tu misma semántica de errores
        } catch (RuntimeException e) {
            log.error("Error al desvincular policies del rol '{}': {}", roleName, e.getMessage(), e);
            throw e;
        }

        try {
            roleResource.remove();
            log.info("Perfil '{}' eliminado correctamente", roleName);
        } catch (ClientErrorException cee) {
            int status = cee.getResponse() != null ? cee.getResponse().getStatus() : 500;
            log.error("Error de Keycloak al eliminar perfil ({}). Status={} - {}", roleName, status, cee.getMessage(),
                    cee);
            if (status == 404)
                throw new ResourceNotFoundException("No se encontró el perfil");
            throw new RuntimeException("Error de Keycloak (" + status + "): " + cee.getMessage(), cee);
        }
    }

    /**
     * Actualiza un perfil existente en Keycloak.
     * <p>
     * Permite cambiar nombre y descripción, verificando que el nuevo nombre no esté
     * duplicado.
     * </p>
     *
     * @param profileId  identificador del perfil a actualizar.
     * @param profileDTO nuevos datos del perfil.
     * @return el perfil actualizado como {@link ProfileDTO}.
     * @throws ConflictException         si ya existe un perfil con el nuevo nombre.
     * @throws ResourceNotFoundException si el perfil no existe.
     */
    @Override
    @Auditable(operationType = OperationType.UPDATE, affectedTable = "PROFILE")
    public ProfileDTO updateProfile(String profileId, ProfileDTO profileDTO) {
        RealmResource realm = keycloakProvider.getRealmResource();

        RoleRepresentation existingRole = realm.roles().list().stream()
                .filter(role -> profileId.equals(role.getId()))
                .findFirst()
                .orElseThrow(() -> new ResourceNotFoundException("No se encontró el perfil con ID " + profileId));

        String currentRoleName = existingRole.getName();
        String newRoleName = profileDTO.getName();

        if (!currentRoleName.equals(newRoleName)) {
            try {
                realm.roles().get(newRoleName).toRepresentation();
                throw new ConflictException("El nombre del perfil ya existe");
            } catch (NotFoundException notExists) {
            }
        }

        RoleRepresentation updated = new RoleRepresentation();
        updated.setName(newRoleName);
        updated.setDescription(profileDTO.getDescription());

        try {
            realm.roles().get(currentRoleName).update(updated);
            RoleRepresentation finalRep = realm.roles().get(newRoleName).toRepresentation();
            log.info("Perfil '{}' actualizado correctamente a '{}'", currentRoleName, newRoleName);
            return ProfileDTO.builder()
                    .id(finalRep.getId())
                    .name(finalRep.getName())
                    .description(finalRep.getDescription())
                    .build();
        } catch (ClientErrorException cee) {
            int status = cee.getResponse() != null ? cee.getResponse().getStatus() : 500;
            log.error("Error de Keycloak al actualizar perfil ({} -> {}). Status={} - {}", currentRoleName, newRoleName,
                    status, cee.getMessage(), cee);
            if (status == 404)
                throw new ResourceNotFoundException("No se encontró el perfil");
            if (status == 409)
                throw new ConflictException("El nombre del perfil ya existe");
            throw new RuntimeException("Error de Keycloak (" + status + "): " + cee.getMessage(), cee);
        }
    }

    /**
     * Busca perfiles por su nombre en Keycloak.
     *
     * @param name nombre del perfil a buscar.
     * @return lista de perfiles encontrados como {@link ProfileDTO}.
     */
    @Override
    public List<ProfileDTO> findProfilesByName(String name) {
        return keycloakProvider.getRealmResource()
                .roles()
                .list()
                .stream()
                .filter(role -> role.getName().equalsIgnoreCase(name))
                .map(role -> ProfileDTO.builder()
                        .id(role.getId())
                        .name(role.getName())
                        .description(role.getDescription())
                        .build())
                .toList();
    }
}
