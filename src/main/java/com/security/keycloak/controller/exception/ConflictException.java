package com.security.keycloak.controller.exception;

/**
 * Excepción personalizada para manejar conflictos en la aplicación.
 * <p>
 * Esta excepción se lanza cuando ocurre una situación de conflicto, por ejemplo,
 * cuando se intenta crear un recurso que ya existe en el sistema.
 * </p>
 */
public class ConflictException extends RuntimeException {

    /**
     * Constructor que recibe un mensaje personalizado para describir el conflicto.
     *
     * @param message Mensaje explicativo del conflicto ocurrido.
     */
    public ConflictException(String message) {
        super(message);
    }

    /**
     * Constructor que construye un mensaje de conflicto más detallado indicando
     * el recurso, el campo y el valor que ya existe.
     *
     * @param resourceName Nombre del recurso que causó el conflicto.
     * @param fieldName    Nombre del campo que genera el conflicto.
     * @param fieldValue   Valor del campo que ya existe en el recurso.
     */
    public ConflictException(String resourceName, String fieldName, Object fieldValue) {
        super(String.format("%s ya existe con %s: '%s'", resourceName, fieldName, fieldValue));
    }
}
