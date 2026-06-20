package com.security.keycloak.service;

import java.util.List;
import java.util.Map;

/**
 * Interfaz de servicio para la gestión de permisos en Keycloak.
 * <p>
 * Define operaciones para consultar, asignar y actualizar permisos asociados
 * a roles dentro del sistema.
 * </p>
 */
public interface IPermissionKeycloakService {

    /**
     * Obtiene todos los permisos disponibles en el sistema.
     *
     * @return lista de permisos representados como cadenas.
     */
    List<String> findAllPermissions();

    /**
     * Asigna una lista de permisos a una política/rol específico.
     *
     * @param permissions lista de permisos a asignar.
     * @param roleName    nombre del rol al que se le asignarán los permisos.
     * @return {@code true} si la operación fue exitosa, {@code false} en caso contrario.
     */
    boolean addPolicytoPermissions(List<String> permissions, String roleName);

    /**
     * Recupera todos los roles junto con los permisos que tienen asociados.
     *
     * @return un mapa donde la clave es el nombre del rol y el valor es la lista de permisos.
     */
    Map<String, List<String>> getRolesWithPermissions();

    /**
     * Actualiza los permisos asignados a un rol existente.
     *
     * @param newPermissions lista de nuevos permisos a asignar.
     * @param roleName       nombre del rol cuyo conjunto de permisos será actualizado.
     * @return {@code true} si la actualización fue exitosa, {@code false} en caso contrario.
     */
    boolean updatePermissionsForRole(List<String> newPermissions, String roleName);

    /**
     * Desvincula todas las referencias de políticas asociadas a un rol específico.
     *
     * @param roleName nombre del rol cuyas referencias de políticas serán desvinculadas.
     * @return {@code true} si la operación fue exitosa, {@code false} en caso contrario.
     */
    boolean detachPolicyReferencesForRole(String roleName);

}
