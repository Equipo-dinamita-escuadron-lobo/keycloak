package com.security.keycloak.util;

import org.jboss.resteasy.client.jaxrs.internal.ResteasyClientBuilderImpl;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Proveedor de configuración y cliente de conexión a Keycloak.
 * <p>
 * Se encarga de inicializar un cliente {@link Keycloak} utilizando
 * las credenciales de administración configuradas en el archivo de propiedades.
 * Proporciona métodos de utilidad para acceder a recursos del realm y usuarios.
 * </p>
 */
@Component
public class KeycloakProvider {

    /**
     * Nombre del realm configurado en el sistema.
     */
    private final String realmName;

    /**
     * Cliente de administración de Keycloak utilizado para realizar operaciones.
     */
    private final Keycloak keycloak;

    /**
     * Constructor que inicializa el cliente de Keycloak con los parámetros de configuración.
     *
     * @param serverUrl   URL base del servidor Keycloak.
     * @param realmMaster Realm maestro utilizado para autenticación administrativa.
     * @param realmName   Nombre del realm de aplicación.
     * @param clientId    ID del cliente configurado para administración.
     * @param clientSecret Secreto del cliente (opcional, puede ser vacío).
     * @param username    Usuario administrador de consola.
     * @param password    Contraseña del usuario administrador.
     */
    public KeycloakProvider(
            @Value("${keycloak.server.url}") String serverUrl,
            @Value("${keycloak.realm.master}") String realmMaster,
            @Value("${keycloak.realm.name}") String realmName,
            @Value("${keycloak.admin}") String clientId,
            @Value("${keycloak.client.secret:}") String clientSecret,
            @Value("${keycloak.user.console}") String username,
            @Value("${keycloak.password}") String password
    ) {
        this.realmName = realmName;

        KeycloakBuilder builder = KeycloakBuilder.builder()
                .serverUrl(serverUrl)
                .realm(realmMaster)
                .clientId(clientId)
                .username(username)
                .password(password)
                .resteasyClient(new ResteasyClientBuilderImpl()
                        .connectionPoolSize(10)
                        .build());

        if (clientSecret != null && !clientSecret.isBlank()) {
            builder.clientSecret(clientSecret);
        }

        this.keycloak = builder.build();
    }

    /**
     * Obtiene el recurso del realm configurado en Keycloak.
     *
     * @return recurso {@link RealmResource} del realm.
     */
    public RealmResource getRealmResource() {
        return keycloak.realm(realmName);
    }

    /**
     * Obtiene el recurso de usuarios asociado al realm configurado.
     *
     * @return recurso {@link UsersResource} del realm.
     */
    public UsersResource getUserResource() {
        return getRealmResource().users();
    }

    /**
     * Obtiene el token de acceso del administrador configurado.
     *
     * @return token de acceso como {@link String}.
     */
    public String getAdminAccessToken() {
        return keycloak.tokenManager().getAccessTokenString();
    }

    /** Buscar usuario por email y lanzar si no existe */
    public org.keycloak.representations.idm.UserRepresentation findUserByEmailOrThrow(String email) {
        var users = getUserResource().searchByEmail(email, true);
        if (users == null || users.isEmpty()) throw new RuntimeException("Usuario no encontrado");
        return users.get(0);
    }

    /** Resetear password del usuario */
    public void resetUserPassword(String userId, String newPassword) {
        var cred = new org.keycloak.representations.idm.CredentialRepresentation();
        cred.setType(org.keycloak.representations.idm.CredentialRepresentation.PASSWORD);
        cred.setTemporary(false);
        cred.setValue(newPassword);
        getUserResource().get(userId).resetPassword(cred);
    }

    /** Revocar sesiones/tokens del usuario a partir del access token */
    public void revoke(String accessToken) {
        try {
        String userId = com.security.keycloak.util.JwtUtils.getSub(accessToken);
        if (userId != null) {
            getRealmResource().users().get(userId).logout();
        }
        } catch (Exception ignore) { /* noop */ }
    }
}
