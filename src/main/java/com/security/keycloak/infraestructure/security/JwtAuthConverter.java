package com.security.keycloak.infraestructure.security;

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
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * JwtAuthConverter es un componente que convierte un objeto Jwt en un AbstractAuthenticationToken.
 * Implementa la interfaz Converter de Spring Security y la interfaz IJwtUtils.
 */
@Component
public class JwtAuthConverter implements Converter<Jwt, AbstractAuthenticationToken> , IJwtUtils{

    private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

    @Value("${jwt.auth.converter.principle-attribute}")
    private String principleAtrribute;

    @Value("${jwt.auth.converter.resource-id}")
    private String resourceId;

    /**
     * Convierte un objeto Jwt en un AbstractAuthenticationToken.
     * 
     * @param jwt el objeto Jwt a convertir.
     * @return el AbstractAuthenticationToken convertido.
     */
    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        
        // Combina las autoridades otorgadas por JwtGrantedAuthoritiesConverter y las extraídas del JWT.
        Collection<GrantedAuthority> authorities = Stream
            .concat(jwtGrantedAuthoritiesConverter.convert(jwt).stream(), extractResourceRoles(jwt).stream())
            .toList();

        return new JwtAuthenticationToken(jwt, authorities, getPrincipleName(jwt));
        
    }

    /**
     * Obtiene el nombre del principio del JWT.
     * 
     * @param jwt el objeto Jwt del que se extrae el nombre del principio.
     * @return el nombre del principio.
     */
    private String getPrincipleName(Jwt jwt) {
        String claimName = JwtClaimNames.SUB;

        if(principleAtrribute != null) {
            claimName = principleAtrribute;
        }

        return jwt.getClaim(claimName);
    }

    /**
     * Extrae los roles de recursos del JWT.
     * 
     * @param jwt el objeto Jwt del que se extraen los roles.
     * @return una colección de GrantedAuthority correspondiente a los roles.
     */
    @SuppressWarnings("unchecked")
    private Collection<? extends GrantedAuthority> extractResourceRoles(Jwt jwt) {
        Map<String, Object> resourceAccess;
        Map<String, Object> resource;
        Collection<String> resourceRoles;

        // Extrae el acceso a los recursos del JWT.
        resourceAccess = jwt.getClaim("resource_access");

        if(resourceAccess == null) {
            return List.of();           
        }

        // Extrae los recursos específicos por ID.
        resource = (Map<String, Object>) resourceAccess.get(resourceId);

        if(resourceAccess.get(resourceId) == null) {
            return List.of();
        }


        if(resource.get("roles") == null) {
            return List.of();
        }

        // Obtiene los roles del recurso.
        resourceRoles = (Collection<String>) resource.get("roles");

        // Convierte cada rol en una autoridad otorgada y retorna la colección resultante.
        return resourceRoles.stream()
            .map(role -> new SimpleGrantedAuthority("ROLE_".concat(role)))
            .toList();
    }

    /**
     * Obtiene el id del usuario.
     * @return id del usuario
     */
    @Override
    public String getUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof JwtAuthenticationToken jwtAuthenticationToken) {
            return jwtAuthenticationToken.getToken().getSubject();
        }
        throw new IllegalStateException("No authenticated JWT is available in the current request");
    }
    
}
