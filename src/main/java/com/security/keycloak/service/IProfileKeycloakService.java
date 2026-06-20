package com.security.keycloak.service;

import java.util.List;

import com.security.keycloak.dtos.ProfileDTO;

/**
 * Interfaz de servicio para la gestión de perfiles en Keycloak.
 * <p>
 * Define las operaciones disponibles para consultar, crear, actualizar
 * y eliminar perfiles dentro del sistema.
 * </p>
 */
public interface IProfileKeycloakService {

    /**
     * Obtiene todos los perfiles disponibles en el sistema.
     *
     * @return lista de perfiles representados como {@link ProfileDTO}.
     */
    List<ProfileDTO> findAllProfiles();

    /**
     * Busca un perfil por su identificador único.
     *
     * @param profileId identificador del perfil.
     * @return el perfil encontrado como {@link ProfileDTO}.
     */
    ProfileDTO findProfileById(String profileId);

    /**
     * Busca perfiles cuyo nombre coincida con el parámetro dado.
     *
     * @param name nombre del perfil a buscar.
     * @return lista de perfiles coincidentes representados como {@link ProfileDTO}.
     */
    List<ProfileDTO> findProfilesByName(String name);

    /**
     * Crea un nuevo perfil en el sistema.
     *
     * @param profileDTO objeto con los datos del perfil a crear.
     * @return el perfil creado representado como {@link ProfileDTO}.
     */
    ProfileDTO createProfile(ProfileDTO profileDTO);

    /**
     * Elimina un perfil existente del sistema.
     *
     * @param profileId identificador del perfil a eliminar.
     */
    void deleteProfile(String profileId);

    /**
     * Actualiza los datos de un perfil existente.
     *
     * @param profileId  identificador del perfil a actualizar.
     * @param profileDTO objeto con los datos nuevos del perfil.
     * @return el perfil actualizado representado como {@link ProfileDTO}.
     */
    ProfileDTO updateProfile(String profileId, ProfileDTO profileDTO);
}
