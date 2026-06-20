package com.security.keycloak.controller.exception;

import java.time.LocalDateTime;

import com.fasterxml.jackson.annotation.JsonFormat;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.Builder;

/**
 * Clase que representa la estructura de una respuesta de error estándar
 * utilizada en la aplicación.
 * <p>
 * Proporciona información detallada sobre el error ocurrido, incluyendo
 * el código de estado HTTP, el mensaje, la ruta y la marca de tiempo.
 * </p>
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ErrorResponse {

    /**
     * Código de estado HTTP del error.
     */
    private int statusCode;

    /**
     * Tipo o nombre del error.
     */
    private String error;

    /**
     * Mensaje descriptivo que explica la causa del error.
     */
    private String message;

    /**
     * Fecha y hora en que ocurrió el error, con formato dd-MM-yyyy HH:mm:ss.
     */
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "dd-MM-yyyy HH:mm:ss")
    private LocalDateTime timestamp;

    /**
     * Ruta del endpoint en el que se produjo el error.
     */
    private String path;
}
