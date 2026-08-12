package com.security.keycloak.infraestructure.output.keycloakAdapter;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.security.keycloak.application.output.IAuthOutputPort;
import com.security.keycloak.domain.models.User;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

/**
 * AuthAdapter es un componente que implementa la interfaz IAuthOutputPort y proporciona
 * métodos para obtener el usuario actual a partir de un token JWT.
*/
@Component
public class AuthAdapter implements IAuthOutputPort{

    @Value("${jwt.public.key}")
    private  String publicKeyString;

    @Value("${jwt.auth.converter.resource-id}")
    private String resourceId;

    /**
     * Obtiene el usuario actual a partir del encabezado de autorización.
     *
     * @param authorizationHeader el encabezado de autorización que contiene el token JWT.
     * @return el usuario extraído del JWT, o null si el token no es válido.
     */
    @Override
    public User getCurrentUser(String authorizationHeader) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String jwt = null;
         // Extrae el token JWT del encabezado de autorización.
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            jwt = authorizationHeader.substring(7);
        }

        if (jwt != null) {
            // Obtiene la clave pública para verificar el token.
            PublicKey publicKey = getPublicKey(publicKeyString);
            // Analiza y verifica el token JWT.
            Claims claims = Jwts.parser().setSigningKey(publicKey).parseClaimsJws(jwt).getBody();

            // Crea un objeto User a partir de los claims del token.
            @SuppressWarnings("unchecked")
            Map<String, Object> resourceAccess = claims.get("resource_access", Map.class);
            Map<String, Object> clientAccess = resourceAccess == null
                    ? null : (Map<String, Object>) resourceAccess.get(resourceId);
            List<String> roles = clientAccess == null
                    ? List.of() : (List<String>) clientAccess.getOrDefault("roles", List.of());

            User user = User.builder()
            .id(claims.get("sub").toString())
            .username(claims.get("preferred_username").toString())
            .email("** email **")
            .firstName(claims.get("given_name").toString())
            .lastName(claims.get("family_name").toString())
            .roles(roles)
            .build();

            return user;
        } else {
            return null;
        }
    }
    /**
     * Obtiene la clave pública a partir de una cadena codificada en Base64.
     *
     * @param publicKeyString la cadena que contiene la clave pública codificada.
     * @return la clave pública.
     * @throws NoSuchAlgorithmException si el algoritmo RSA no está disponible.
     * @throws InvalidKeySpecException si la especificación de la clave pública es inválida.
     */
    private PublicKey getPublicKey(String publicKeyString) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }
    
}
