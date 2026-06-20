package com.security.keycloak.controller.exception;

/**
 * Excepción personalizada para manejar escenarios en los que un recurso no es encontrado.
 * <p>
 * Se utiliza cuando se intenta acceder a un recurso que no existe en el sistema,
 * proporcionando un mensaje claro sobre qué entidad y qué valor no se encontró.
 * </p>
 */
public class ResourceNotFoundException extends RuntimeException {

    /**
     * Constructor que recibe un mensaje personalizado para describir el error.
     *
     * @param message Mensaje explicativo indicando el recurso no encontrado.
     */
    public ResourceNotFoundException(String message) {
        super(message);
    }

    /**
     * Constructor que construye un mensaje detallado indicando el recurso,
     * el campo y el valor que no fue encontrado.
     *
     * @param resourceName Nombre del recurso que no fue encontrado.
     * @param fieldName    Nombre del campo que se usó en la búsqueda.
     * @param fieldValue   Valor del campo que no fue encontrado.
     */
    public ResourceNotFoundException(String resourceName, String fieldName, Object fieldValue) {
        super(String.format("%s no encontrado con %s: '%s'", resourceName, fieldName, fieldValue));
    }
}
