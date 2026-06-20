package com.security.keycloak.config;

import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * Conversor personalizado de JWT a {@link AbstractAuthenticationToken}.
 * <p>
 * Extrae las autoridades del token JWT, incluyendo los roles definidos en el claim
 * {@code resource_access}, y construye un objeto de autenticación para Spring Security.
 * </p>
 * <p>
 * También implementa la interfaz {@link IJwtUtils} para exponer utilidades como
 * obtener el identificador del usuario autenticado.
 * </p>
 */
@Component
public class JwtAuthConverter implements Converter<Jwt, AbstractAuthenticationToken>, IJwtUtils {

    /**
     * Conversor por defecto de roles a autoridades de Spring Security.
     */
    private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

    /**
     * Atributo del token que se usará como identificador principal del usuario.
     * Configurado mediante {@code jwt.auth.converter.principle-attribute}.
     */
    @Value("${jwt.auth.converter.principle-attribute}")
    private String principleAtrribute;

    /**
     * Identificador del recurso (cliente) dentro del claim {@code resource_access}.
     * Configurado mediante {@code jwt.auth.converter.resource-id}.
     */
    @Value("${jwt.auth.converter.resource-id}")
    private String resourceId;

    /**
     * Token JWT actual, guardado para su reutilización en métodos auxiliares.
     */
    Jwt jwtToken;

    /**
     * Convierte un token JWT en un objeto de autenticación de Spring Security,
     * incluyendo las autoridades estándar y las extraídas del recurso configurado.
     *
     * @param jwt token JWT recibido en la autenticación.
     * @return objeto {@link JwtAuthenticationToken} con el usuario y sus roles.
     */
    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {

        Collection<GrantedAuthority> authorities = Stream
            .concat(jwtGrantedAuthoritiesConverter.convert(jwt).stream(), extractResourceRoles(jwt).stream())
            .toList();

        this.jwtToken = jwt;

        return new JwtAuthenticationToken(jwt, authorities, getPrincipleName(jwt));
    }

    /**
     * Obtiene el atributo definido como identificador principal del usuario.
     * Por defecto utiliza {@code sub}, pero puede configurarse en propiedades.
     *
     * @param jwt token JWT.
     * @return valor del claim que representa el identificador del usuario.
     */
    private String getPrincipleName(Jwt jwt) {
        String claimName = JwtClaimNames.SUB;

        if (principleAtrribute != null) {
            claimName = principleAtrribute;
        }

        return jwt.getClaim(claimName);
    }

    /**
     * Extrae los roles del recurso configurado en el claim {@code resource_access}.
     * Los roles se transforman en autoridades de Spring con el prefijo {@code ROLE_}.
     *
     * @param jwt token JWT.
     * @return colección de roles como {@link GrantedAuthority}.
     */
    @SuppressWarnings("unchecked")
    private Collection<? extends GrantedAuthority> extractResourceRoles(Jwt jwt) {
        Map<String, Object> resourceAccess;
        Map<String, Object> resource;
        Collection<String> resourceRoles;

        resourceAccess = jwt.getClaim("resource_access");

        if (resourceAccess == null) {
            return List.of();
        }

        resource = (Map<String, Object>) resourceAccess.get(resourceId);

        if (resourceAccess.get(resourceId) == null) {
            return List.of();
        }

        if (resource.get("roles") == null) {
            return List.of();
        }

        resourceRoles = (Collection<String>) resource.get("roles");

        return resourceRoles.stream()
            .map(role -> new SimpleGrantedAuthority("ROLE_".concat(role)))
            .toList();
    }

    /**
     * Obtiene el identificador único del usuario desde el claim {@code sub}.
     *
     * @return ID del usuario autenticado.
     */
    @Override
    public String getUserId() {
        return (String) jwtToken.getClaims().get("sub");
    }
}
