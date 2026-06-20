package com.security.keycloak.controller.exception;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.client.RestClientException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import lombok.extern.slf4j.Slf4j;

/**
 * Manejador global de excepciones para la aplicación.
 * <p>
 * Esta clase centraliza el tratamiento de excepciones lanzadas en los controladores,
 * generando respuestas consistentes con un objeto {@link ErrorResponse}.
 * </p>
 * <p>
 * Proporciona manejadores para errores comunes como validación, acceso denegado,
 * recurso no encontrado, conflictos, autenticación y errores internos del servidor.
 * </p>
 */
@Slf4j
@ControllerAdvice
public class GlobalExceptionHandler {

    /**
     * Manejo de errores de validación de {@code @Valid} en {@code @RequestBody}.
     * <p>
     * Se activa cuando un objeto enviado en el cuerpo de la petición no cumple
     * con las validaciones definidas. Devuelve un código de estado 400 (Bad Request).
     * </p>
     *
     * @param ex      excepción lanzada por validaciones fallidas.
     * @param request solicitud HTTP que produjo el error.
     * @return respuesta con detalles del error de validación.
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidationErrors(
            MethodArgumentNotValidException ex,
            HttpServletRequest request) {

        List<String> details = ex.getBindingResult()
                .getAllErrors()
                .stream()
                .map(error -> {
                    if (error instanceof FieldError fe) {
                        return fe.getField() + ": " + fe.getDefaultMessage();
                    }
                    return error.getDefaultMessage();
                })
                .collect(Collectors.toList());

        String message = String.join(", ", details);

        ErrorResponse error = ErrorResponse.builder()
                .statusCode(HttpStatus.BAD_REQUEST.value())
                .error("Bad Request")
                .message(message)
                .timestamp(LocalDateTime.now())
                .path(request.getRequestURI())
                .build();

        return ResponseEntity.badRequest().body(error);
    }

    /**
     * Manejo de errores de validación en parámetros como {@code @PathVariable}
     * y {@code @RequestParam}.
     * <p>
     * Se activa cuando un parámetro de la URL o de la petición no cumple con
     * las restricciones establecidas. Devuelve un código de estado 400 (Bad Request).
     * </p>
     *
     * @param ex      excepción de violación de restricción.
     * @param request solicitud HTTP que produjo el error.
     * @return respuesta con detalles del error de validación de parámetros.
     */
    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ErrorResponse> handleConstraintViolation(
            ConstraintViolationException ex,
            HttpServletRequest request) {

        String message = ex.getConstraintViolations()
                .stream()
                .map(v -> v.getPropertyPath() + ": " + v.getMessage())
                .collect(Collectors.joining(", "));

        ErrorResponse error = ErrorResponse.builder()
                .statusCode(HttpStatus.BAD_REQUEST.value())
                .error("Bad Request")
                .message(message)
                .timestamp(LocalDateTime.now())
                .path(request.getRequestURI())
                .build();

        return ResponseEntity.badRequest().body(error);
    }

    /**
     * Manejo de errores de validación custom como @Sanitize.
     * <p>
     * Se activa cuando un campo con @Sanitize falla la validación.
     * Devuelve un código de estado 400 (Bad Request).
     * </p>
     *
     * @param ex      excepción de validación custom.
     * @param request solicitud HTTP que produjo el error.
     * @return respuesta con detalles del error de sanitización.
     */
    @ExceptionHandler(jakarta.validation.ValidationException.class)
    public ResponseEntity<ErrorResponse> handleCustomValidation(
            jakarta.validation.ValidationException ex,
            HttpServletRequest request) {

        ErrorResponse error = ErrorResponse.builder()
                .statusCode(HttpStatus.BAD_REQUEST.value())
                .error("Bad Request")
                .message(ex.getMessage())
                .timestamp(LocalDateTime.now())
                .path(request.getRequestURI())
                .build();

        return ResponseEntity.badRequest().body(error);
    }

    /**
     * Manejo de acceso denegado.
     * <p>
     * Se activa cuando un usuario intenta acceder a un recurso sin permisos suficientes.
     * Devuelve un código de estado 403 (Forbidden).
     * </p>
     *
     * @param ex      excepción de acceso denegado.
     * @param request solicitud HTTP que produjo el error.
     * @return respuesta con detalles del error de autorización.
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDenied(
            AccessDeniedException ex,
            HttpServletRequest request) {

        ErrorResponse error = ErrorResponse.builder()
                .statusCode(HttpStatus.FORBIDDEN.value())
                .error("Forbidden")
                .message("No autorizado para acceder a este recurso")
                .timestamp(LocalDateTime.now())
                .path(request.getRequestURI())
                .build();

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(error);
    }

    /**
     * Manejo de recurso no encontrado.
     * <p>
     * Se activa cuando se intenta acceder a un recurso inexistente.
     * Devuelve un código de estado 404 (Not Found).
     * </p>
     *
     * @param ex      excepción de recurso no encontrado.
     * @param request solicitud HTTP que produjo el error.
     * @return respuesta con detalles del error de recurso inexistente.
     */
    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleNotFound(
            ResourceNotFoundException ex,
            HttpServletRequest request) {

        ErrorResponse error = ErrorResponse.builder()
                .statusCode(HttpStatus.NOT_FOUND.value())
                .error("Not Found")
                .message(ex.getMessage() != null ? ex.getMessage() : "No se encontró el perfil")
                .timestamp(LocalDateTime.now())
                .path(request.getRequestURI())
                .build();

        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
    }

    /**
     * Manejo de conflictos.
     * <p>
     * Se activa en casos como duplicidad de datos o reglas de negocio que
     * impiden completar la operación. Devuelve un código de estado 409 (Conflict).
     * </p>
     *
     * @param ex      excepción de conflicto.
     * @param request solicitud HTTP que produjo el error.
     * @return respuesta con detalles del conflicto detectado.
     */
    @ExceptionHandler(ConflictException.class)
    public ResponseEntity<ErrorResponse> handleConflict(
            ConflictException ex,
            HttpServletRequest request) {

        ErrorResponse error = ErrorResponse.builder()
                .statusCode(HttpStatus.CONFLICT.value())
                .error("Conflict")
                .message(ex.getMessage())
                .timestamp(LocalDateTime.now())
                .path(request.getRequestURI())
                .build();

        return ResponseEntity.status(HttpStatus.CONFLICT).body(error);
    }

    /**
     * Manejo de excepciones de usuario.
     * <p>
     * Se activa para excepciones personalizadas de usuario.
     * Devuelve el código de estado especificado en la excepción.
     * </p>
     *
     * @param ex      excepción de usuario.
     * @param request solicitud HTTP que produjo el error.
     * @return respuesta con detalles del error de usuario.
     */
    @ExceptionHandler(UserException.class)
    public ResponseEntity<ErrorResponse> handleUserException(
            UserException ex,
            HttpServletRequest request) {

        HttpStatus status = HttpStatus.valueOf(ex.getStatus());
        
        log.warn("UserException: {} - Status: {}", ex.getMessage(), ex.getStatus());

        ErrorResponse error = ErrorResponse.builder()
                .statusCode(ex.getStatus())
                .error(status.getReasonPhrase())
                .message(ex.getMessage())
                .timestamp(LocalDateTime.now())
                .path(request.getRequestURI())
                .build();

        return ResponseEntity.status(status).body(error);
    }

    /**
     * Manejo de errores de cliente REST (RestClientException).
     * <p>
     * Se activa cuando hay errores en llamadas REST, como problemas de autenticación con Keycloak.
     * </p>
     *
     * @param ex      excepción de cliente REST.
     * @param request solicitud HTTP que produjo el error.
     * @return respuesta con detalles del error.
     */
    @ExceptionHandler(RestClientException.class)
    public ResponseEntity<ErrorResponse> handleRestClientError(
            RestClientException ex,
            HttpServletRequest request) {

        log.error("Error en llamada REST: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.builder()
                .statusCode(HttpStatus.UNAUTHORIZED.value())
                .error("Unauthorized")
                .message("Error de autenticación. Por favor verifica tus credenciales.")
                .timestamp(LocalDateTime.now())
                .path(request.getRequestURI())
                .build();

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
    }

    /**
     * Manejo de IllegalArgumentException.
     * <p>
     * Se activa cuando se proporcionan argumentos inválidos.
     * Devuelve un código de estado 400 (Bad Request).
     * </p>
     *
     * @param ex      excepción de argumento ilegal.
     * @param request solicitud HTTP que produjo el error.
     * @return respuesta con detalles del error.
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgument(
            IllegalArgumentException ex,
            HttpServletRequest request) {

        log.warn("Argumento inválido: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.builder()
                .statusCode(HttpStatus.BAD_REQUEST.value())
                .error("Bad Request")
                .message(ex.getMessage())
                .timestamp(LocalDateTime.now())
                .path(request.getRequestURI())
                .build();

        return ResponseEntity.badRequest().body(error);
    }

    /**
     * Manejo de IllegalStateException.
     * <p>
     * Se activa cuando el estado de la aplicación no permite la operación.
     * Devuelve un código de estado 409 (Conflict).
     * </p>
     *
     * @param ex      excepción de estado ilegal.
     * @param request solicitud HTTP que produjo el error.
     * @return respuesta con detalles del error.
     */
    @ExceptionHandler(IllegalStateException.class)
    public ResponseEntity<ErrorResponse> handleIllegalState(
            IllegalStateException ex,
            HttpServletRequest request) {

        log.warn("Estado ilegal: {}", ex.getMessage());

        ErrorResponse error = ErrorResponse.builder()
                .statusCode(HttpStatus.CONFLICT.value())
                .error("Conflict")
                .message(ex.getMessage())
                .timestamp(LocalDateTime.now())
                .path(request.getRequestURI())
                .build();

        return ResponseEntity.status(HttpStatus.CONFLICT).body(error);
    }

    /**
     * Manejo genérico de excepciones no controladas.
     * <p>
     * Se activa para cualquier error inesperado en la aplicación.
     * Devuelve un código de estado 500 (Internal Server Error).
     * </p>
     *
     * @param ex      excepción genérica.
     * @param request solicitud HTTP que produjo el error.
     * @return respuesta con detalles del error interno del servidor.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGeneric(
            Exception ex,
            HttpServletRequest request) {

        log.error("Error inesperado: ", ex);

        ErrorResponse error = ErrorResponse.builder()
                .statusCode(HttpStatus.INTERNAL_SERVER_ERROR.value())
                .error("Internal Server Error")
                .message("Error interno del servidor")
                .timestamp(LocalDateTime.now())
                .path(request.getRequestURI())
                .build();

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
    }
}
