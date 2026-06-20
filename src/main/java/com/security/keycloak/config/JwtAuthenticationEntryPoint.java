package com.security.keycloak.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.keycloak.controller.exception.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.LocalDateTime;

/**
 * Punto de entrada para manejar errores de autenticación JWT.
 * <p>
 * Cuando un usuario no autenticado intenta acceder a un recurso protegido,
 * esta clase captura la excepción y devuelve una respuesta JSON estructurada
 * con detalles del error.
 * </p>
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    /** Mapeador de objetos para convertir respuestas a JSON. */
    private final ObjectMapper objectMapper;

    /**
     * Maneja la excepción de autenticación y construye una respuesta JSON.
     *
     * @param request       la solicitud HTTP entrante.
     * @param response      la respuesta HTTP saliente.
     * @param authException la excepción de autenticación lanzada.
     * @throws IOException en caso de error al escribir la respuesta.
     */
    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authException) throws IOException {

        log.warn("Acceso no autorizado: {}", authException.getMessage());

        ErrorResponse error = ErrorResponse.builder()
                .statusCode(HttpStatus.UNAUTHORIZED.value())
                .error("Unauthorized")
                .message("Token inválido o ausente")
                .timestamp(LocalDateTime.now())
                .path(request.getRequestURI())
                .build();

                

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType("application/json");
        response.getWriter().write(objectMapper.writeValueAsString(error));
    }
}