package com.security.keycloak.service.impl;

import com.security.keycloak.controller.exception.ConflictException;
import com.security.keycloak.controller.exception.ResourceNotFoundException;
import com.security.keycloak.dtos.ProfileDTO;
import com.security.keycloak.service.IPermissionKeycloakService;
import com.security.keycloak.util.KeycloakProvider;
import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.RoleResource;
import org.keycloak.admin.client.resource.RolesResource;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;

/**
 * Suite de pruebas unitarias para {@link ProfileKeycloakServiceImpl}.
 * <p>
 * Verifica la lógica de negocio para crear, buscar, actualizar y eliminar perfiles (roles)
 * en Keycloak, utilizando el cliente de administración mockeado. Las pruebas:
 * </p>
 * <ul>
 *   <li>No levantan contexto de Spring.</li>
 *   <li>No realizan llamadas reales a Keycloak (todo es con Mockito).</li>
 *   <li>No prueban código generado (Lombok) ni configuración.</li>
 *   <li>Validan rutas felices y el mapeo de errores (404, 409, otros 4xx) a excepciones de dominio.</li>
 * </ul>
 * <p>
 * Herramientas: JUnit 5 (Jupiter), Mockito, AssertJ. Se mockean {@link KeycloakProvider},
 * {@link RealmResource}, {@link RolesResource} y {@link RoleResource}.
 * </p>
 */
@ExtendWith(MockitoExtension.class)
class ProfileKeycloakServiceImplUnitTest {

    @Mock KeycloakProvider keycloakProvider;
    @Mock IPermissionKeycloakService permissionKeycloakService;

    @Mock RealmResource realm;
    @Mock RolesResource roles;
    @Mock RoleResource roleResource;

    @InjectMocks ProfileKeycloakServiceImpl service;

    /**
     * Configuración base: devuelve el {@link RealmResource} y sus {@link RolesResource} mockeados.
     */
    @BeforeEach
    void setup() {
        when(keycloakProvider.getRealmResource()).thenReturn(realm);
        when(realm.roles()).thenReturn(roles);
    }

    /** Utilidad para construir un {@link RoleRepresentation} mínimo. */
    private static RoleRepresentation role(String id, String name, String desc) {
        RoleRepresentation r = new RoleRepresentation();
        r.setId(id);
        r.setName(name);
        r.setDescription(desc);
        return r;
    }

    // ------------------------ findAllProfiles ------------------------

    /**
     * Debe excluir roles por defecto y mapear los restantes a DTO.
     */
    @Test
    void findAllProfiles_excludesDefaultRolesAndMapsDto() {
        List<RoleRepresentation> kcRoles = List.of(
                role("1", "admin", "Administrador"),
                role("2", "uma_authorization", "sys"),
                role("3", "offline_access", "sys"),
                role("4", "custom", "Personalizado"));
        when(roles.list()).thenReturn(kcRoles);

        var result = service.findAllProfiles();

        assertThat(result)
                .extracting(ProfileDTO::getName)
                .containsExactlyInAnyOrder("admin", "custom")
                .doesNotContain("uma_authorization", "offline_access");

        assertThat(result.stream()
                .filter(p -> p.getName().equals("admin"))
                .findFirst()).get()
                .satisfies(p -> {
                    assertThat(p.getId()).isEqualTo("1");
                    assertThat(p.getDescription()).isEqualTo("Administrador");
                });
    }

    /**
     * Lista vacía → resultado vacío.
     */
    @Test
    void findAllProfiles_returnsEmptyWhenNoRoles() {
        when(roles.list()).thenReturn(List.of());
        assertThat(service.findAllProfiles()).isEmpty();
    }

    /**
     * Debe excluir también los dos default-roles-* adicionales configurados.
     */
    @Test
    void findAllProfiles_excludesBothDefaultRoleNames() {
        when(roles.list()).thenReturn(List.of(
                role("1","default-roles-spring-boot-realm-dev","x"),
                role("2","default-roles-oauth2-realm","x"),
                role("3","keepMe","ok")
        ));

        var result = service.findAllProfiles();
        assertThat(result).hasSize(1);
        assertThat(result.get(0).getName()).isEqualTo("keepMe");
    }

    // ------------------------ findProfileById ------------------------

    /**
     * Busca por ID y mapea correctamente el DTO.
     */
    @Test
    void findProfileById_returnsDto_whenExists() {
        when(roles.list()).thenReturn(List.of(
                role("10", "reader", "Lee cosas"),
                role("11", "writer", "Escribe cosas")
        ));

        var dto = service.findProfileById("11");

        assertThat(dto.getId()).isEqualTo("11");
        assertThat(dto.getName()).isEqualTo("writer");
        assertThat(dto.getDescription()).isEqualTo("Escribe cosas");
    }

    /**
     * Si no encuentra el ID, lanza {@link ResourceNotFoundException}.
     */
    @Test
    void findProfileById_throwsWhenNotFound() {
        when(roles.list()).thenReturn(List.of(role("10", "reader", "Lee cosas")));

        assertThatThrownBy(() -> service.findProfileById("missing"))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("missing");
    }

    // ------------------------ createProfile ------------------------

    /**
     * Crea el rol cuando el nombre no existe previamente (pre-check 404).
     */
    @Test
    void createProfile_creates_whenNameNotExists() {
        String name = "new-role";
        ProfileDTO input = ProfileDTO.builder().name(name).description("Desc").build();

        // 1) Pre-check: NO existe (lanza NotFound)
        when(roles.get(name)).thenReturn(roleResource);
        RoleRepresentation created = role("abc-123", name, "Desc");
        when(roleResource.toRepresentation())
                .thenThrow(new NotFoundException("not exists")) // pre-check
                .thenReturn(created);                           // post-create

        doNothing().when(roles).create(any(RoleRepresentation.class));

        ProfileDTO out = service.createProfile(input);

        assertThat(out.getId()).isEqualTo("abc-123");
        assertThat(out.getName()).isEqualTo(name);
        assertThat(out.getDescription()).isEqualTo("Desc");

        verify(roles).create(argThat(r ->
                name.equals(r.getName()) &&
                "Desc".equals(r.getDescription())));
    }

    /**
     * Si el nombre ya existe (pre-check exitoso), debe lanzar {@link ConflictException}.
     */
    @Test
    void createProfile_throwsConflict_whenNameAlreadyExists() {
        String name = "existing";
        ProfileDTO input = ProfileDTO.builder().name(name).description("x").build();

        when(roles.get(name)).thenReturn(roleResource);
        // Si no lanza NotFound, el rol SÍ existe
        when(roleResource.toRepresentation()).thenReturn(role("id-1", name, "exists"));

        assertThatThrownBy(() -> service.createProfile(input))
                .isInstanceOf(ConflictException.class);
    }

    /**
     * Mapeo de 409 de Keycloak → {@link ConflictException}.
     */
    @Test
    void createProfile_maps409ToConflict() {
        String name = "race-condition";
        ProfileDTO input = ProfileDTO.builder().name(name).description("x").build();

        when(roles.get(name)).thenReturn(roleResource);
        when(roleResource.toRepresentation()).thenThrow(new NotFoundException());

        Response resp409 = Response.status(409).build();
        doThrow(new ClientErrorException("conflict", resp409))
            .when(roles).create(any(RoleRepresentation.class));

        assertThatThrownBy(() -> service.createProfile(input))
            .isInstanceOf(ConflictException.class);
    }

    /**
     * Mapeo de 404 de Keycloak → {@link ResourceNotFoundException}.
     */
    @Test
    void createProfile_maps404ToResourceNotFound_onCreate() {
        String name = "target";
        ProfileDTO input = ProfileDTO.builder().name(name).description("d").build();

        when(roles.get(name)).thenReturn(roleResource);
        when(roleResource.toRepresentation()).thenThrow(new NotFoundException()); // pre-check

        Response resp404 = Response.status(404).build();
        doThrow(new ClientErrorException("nf", resp404))
                .when(roles).create(any(RoleRepresentation.class));

        assertThatThrownBy(() -> service.createProfile(input))
                .isInstanceOf(ResourceNotFoundException.class);
    }

    /**
     * Otros 4xx distintos de 404/409 → {@link RuntimeException} con el código en el mensaje.
     */
    @Test
    void createProfile_mapsOtherStatusToRuntimeException_onCreate() {
        String name = "unknown-error";
        ProfileDTO input = ProfileDTO.builder().name(name).description("d").build();

        when(roles.get(name)).thenReturn(roleResource);
        when(roleResource.toRepresentation()).thenThrow(new NotFoundException()); // pre-check

        Response resp400 = Response.status(400).build();
        doThrow(new ClientErrorException("bad request", resp400))
                .when(roles).create(any(RoleRepresentation.class));

        assertThatThrownBy(() -> service.createProfile(input))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Keycloak (400)");
    }

    // ------------------------ deleteProfile ------------------------

    /**
     * Elimina cuando no hay usuarios asignados; detacha policies y remueve el rol.
     */
    @Test
    void deleteProfile_removes_whenNoUserMembers() {
        RoleRepresentation toDelete = role("rid-1", "roleA", "x");
        when(roles.list()).thenReturn(List.of(toDelete));
        when(roles.get("roleA")).thenReturn(roleResource);
        when(roleResource.getUserMembers()).thenReturn(List.of()); // sin usuarios

        doNothing().when(roleResource).remove();

        service.deleteProfile("rid-1");

        verify(permissionKeycloakService).detachPolicyReferencesForRole("roleA");
        verify(roleResource).remove();
    }

    /**
     * Si getUserMembers() devuelve null, se trata como vacío.
     */
    @Test
    void deleteProfile_treatsNullMembersAsEmpty_andRemoves() {
        RoleRepresentation toDelete = role("rid-10", "roleN", "x");
        when(roles.list()).thenReturn(List.of(toDelete));
        when(roles.get("roleN")).thenReturn(roleResource);
        when(roleResource.getUserMembers()).thenReturn(null);

        doNothing().when(roleResource).remove();

        service.deleteProfile("rid-10");

        verify(permissionKeycloakService).detachPolicyReferencesForRole("roleN");
        verify(roleResource).remove();
    }

    /**
     * Propaga ConflictException desde el detach; no debe llamar remove().
     */
    @Test
    void deleteProfile_propagatesConflict_fromDetach() {
        RoleRepresentation toDelete = role("rid-11", "roleP", "x");
        when(roles.list()).thenReturn(List.of(toDelete));
        when(roles.get("roleP")).thenReturn(roleResource);
        when(roleResource.getUserMembers()).thenReturn(List.of());

        when(permissionKeycloakService.detachPolicyReferencesForRole("roleP"))
                .thenThrow(new ConflictException("conf"));

        assertThatThrownBy(() -> service.deleteProfile("rid-11"))
                .isInstanceOf(ConflictException.class);

        verify(roleResource, never()).remove();
    }

    /**
     * Propaga ResourceNotFoundException desde el detach; no debe llamar remove().
     */
    @Test
    void deleteProfile_propagatesNotFound_fromDetach() {
        RoleRepresentation toDelete = role("rid-12", "roleQ", "x");
        when(roles.list()).thenReturn(List.of(toDelete));
        when(roles.get("roleQ")).thenReturn(roleResource);
        when(roleResource.getUserMembers()).thenReturn(List.of());

        when(permissionKeycloakService.detachPolicyReferencesForRole("roleQ"))
                .thenThrow(new ResourceNotFoundException("nf"));

        assertThatThrownBy(() -> service.deleteProfile("rid-12"))
                .isInstanceOf(ResourceNotFoundException.class);

        verify(roleResource, never()).remove();
    }

    /**
     * Si el rol tiene usuarios, se lanza ConflictException.
     */
    @Test
    void deleteProfile_throwsConflict_whenRoleAssignedToUsers() {
        RoleRepresentation toDelete = role("rid-2", "roleB", "x");
        when(roles.list()).thenReturn(List.of(toDelete));

        when(roles.get("roleB")).thenReturn(roleResource);
        when(roleResource.getUserMembers()).thenReturn(List.of(new UserRepresentation()));

        assertThatThrownBy(() -> service.deleteProfile("rid-2"))
                .isInstanceOf(ConflictException.class);

        verify(roleResource, never()).remove();
    }

    /**
     * Si el ID no existe en el listado, se lanza ResourceNotFoundException.
     */
    @Test
    void deleteProfile_throwsNotFound_whenRoleIdMissing() {
        when(roles.list()).thenReturn(List.of(role("other", "any", "x")));

        assertThatThrownBy(() -> service.deleteProfile("missing"))
                .isInstanceOf(ResourceNotFoundException.class);
    }

    /**
     * Mapeo de 404 al eliminar en Keycloak → ResourceNotFoundException.
     */
    @Test
    void deleteProfile_maps404FromKeycloakToNotFound() {
        RoleRepresentation toDelete = role("rid-3", "roleC", "x");
        when(roles.list()).thenReturn(List.of(toDelete));

        when(roles.get("roleC")).thenReturn(roleResource);
        when(roleResource.getUserMembers()).thenReturn(List.of());

        Response resp404 = Response.status(404).build();
        doThrow(new ClientErrorException("not found", resp404))
                .when(roleResource).remove();

        assertThatThrownBy(() -> service.deleteProfile("rid-3"))
                .isInstanceOf(ResourceNotFoundException.class);

        verify(permissionKeycloakService).detachPolicyReferencesForRole("roleC");
        verify(roleResource).remove();
    }

    // ------------------------ updateProfile ------------------------

    /**
     * Actualiza solo la descripción manteniendo el mismo nombre.
     */
    @Test
    void updateProfile_updatesDescription_whenKeepingSameName() {
        RoleRepresentation existing = role("rid-4", "roleD", "old");
        when(roles.list()).thenReturn(List.of(existing));

        when(roles.get("roleD")).thenReturn(roleResource);
        doNothing().when(roleResource).update(any(RoleRepresentation.class));

        RoleRepresentation finalRep = role("rid-4", "roleD", "newDesc");
        when(roles.get("roleD").toRepresentation()).thenReturn(finalRep);

        ProfileDTO input = ProfileDTO.builder().name("roleD").description("newDesc").build();
        ProfileDTO out = service.updateProfile("rid-4", input);

        assertThat(out.getId()).isEqualTo("rid-4");
        assertThat(out.getName()).isEqualTo("roleD");
        assertThat(out.getDescription()).isEqualTo("newDesc");
    }

    /**
     * Si el nuevo nombre ya existe, se lanza ConflictException.
     */
    @Test
    void updateProfile_throwsConflict_whenNewNameAlreadyExists() {
        RoleRepresentation existing = role("rid-5", "oldName", "x");
        when(roles.list()).thenReturn(List.of(existing));

        when(roles.get("newName")).thenReturn(roleResource);
        // si no lanza NotFound, el nombre está ocupado
        when(roleResource.toRepresentation()).thenReturn(role("rid-x", "newName", "z"));

        ProfileDTO input = ProfileDTO.builder().name("newName").description("d").build();

        assertThatThrownBy(() -> service.updateProfile("rid-5", input))
                .isInstanceOf(ConflictException.class);
    }

    /**
     * Cambia el nombre cuando el nuevo está libre: pre-check NotFound y lectura final del nuevo nombre.
     */
    @Test
    void updateProfile_renames_whenNewNameIsFree() {
        RoleRepresentation existing = role("rid-6", "oldName", "old");
        when(roles.list()).thenReturn(List.of(existing));

        RoleResource newRoleCheckResource = mock(RoleResource.class);
        when(roles.get("newName")).thenReturn(newRoleCheckResource);
        when(newRoleCheckResource.toRepresentation()).thenThrow(new NotFoundException());

        RoleResource oldRoleResource = mock(RoleResource.class);
        when(roles.get("oldName")).thenReturn(oldRoleResource);
        doNothing().when(oldRoleResource).update(any(RoleRepresentation.class));

        RoleResource newRoleAfterUpdate = mock(RoleResource.class);
        RoleRepresentation finalRep = role("rid-6", "newName", "newDesc");
        when(newRoleAfterUpdate.toRepresentation()).thenReturn(finalRep);

        // Secuencia: 1ª vez get("newName") => check (NotFound), 2ª => afterUpdate (ok)
        when(roles.get("newName"))
                .thenReturn(newRoleCheckResource)
                .thenReturn(newRoleAfterUpdate);

        ProfileDTO input = ProfileDTO.builder().name("newName").description("newDesc").build();
        ProfileDTO out = service.updateProfile("rid-6", input);

        assertThat(out.getId()).isEqualTo("rid-6");
        assertThat(out.getName()).isEqualTo("newName");
        assertThat(out.getDescription()).isEqualTo("newDesc");

        verify(oldRoleResource).update(argThat(r ->
                "newName".equals(r.getName()) && "newDesc".equals(r.getDescription())));
    }

    /**
     * Mapeo de 404 desde Keycloak al actualizar → ResourceNotFoundException.
     */
    @Test
    void updateProfile_maps404ToNotFound() {
        RoleRepresentation existing = role("rid-7", "roleX", "old");
        when(roles.list()).thenReturn(List.of(existing));

        RoleResource rr = mock(RoleResource.class);
        when(roles.get("roleX")).thenReturn(rr);

        Response resp404 = Response.status(404).build();
        doThrow(new ClientErrorException("nf", resp404)).when(rr).update(any());

        ProfileDTO input = ProfileDTO.builder().name("roleX").description("d").build();

        assertThatThrownBy(() -> service.updateProfile("rid-7", input))
                .isInstanceOf(ResourceNotFoundException.class);
    }

    /**
     * Mapeo de 409 desde Keycloak al actualizar → ConflictException.
     */
    @Test
    void updateProfile_maps409ToConflict() {
        RoleRepresentation existing = role("rid-20", "roleZ", "old");
        when(roles.list()).thenReturn(List.of(existing));

        RoleResource rr = mock(RoleResource.class);
        when(roles.get("roleZ")).thenReturn(rr);

        Response resp409 = Response.status(409).build();
        doThrow(new ClientErrorException("conflict", resp409)).when(rr).update(any());

        ProfileDTO input = ProfileDTO.builder().name("roleZ").description("d").build();

        assertThatThrownBy(() -> service.updateProfile("rid-20", input))
                .isInstanceOf(ConflictException.class);
    }

    /**
     * Si el profileId no está en la lista inicial, se lanza ResourceNotFoundException.
     */
    @Test
    void updateProfile_throwsNotFound_whenProfileIdMissing() {
        when(roles.list()).thenReturn(List.of()); // no hay roles

        ProfileDTO input = ProfileDTO.builder().name("any").description("d").build();

        assertThatThrownBy(() -> service.updateProfile("rid-missing", input))
                .isInstanceOf(ResourceNotFoundException.class);
    }

    // ------------------------ findProfilesByName ------------------------

    /**
     * Búsqueda case-insensitive + mapeo a DTO.
     */
    @Test
    void findProfilesByName_filtersCaseInsensitiveAndMaps() {
        when(roles.list()).thenReturn(List.of(
                role("1", "Reader", "A"),
                role("2", "reader", "B"),
                role("3", "writer", "C")
        ));

        var result = service.findProfilesByName("reader");

        assertThat(result).hasSize(2);
        assertThat(result).extracting(ProfileDTO::getId).containsExactlyInAnyOrder("1", "2");
        assertThat(result).extracting(ProfileDTO::getDescription).containsExactlyInAnyOrder("A", "B");
    }

    /**
     * Si no hay coincidencias por nombre (case-insensitive), devuelve lista vacía.
     */
    @Test
    void findProfilesByName_returnsEmptyWhenNoMatch() {
        when(roles.list()).thenReturn(List.of(role("1","writer","x")));
        assertThat(service.findProfilesByName("reader")).isEmpty();
    }
}