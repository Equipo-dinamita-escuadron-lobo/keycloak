package com.security.keycloak.audit.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marca un método de servicio como auditable.
 * <p>
 * El aspecto correspondiente intercepta la ejecución del método anotado
 * y publica un {@code OperationEventDto} al exchange de auditoría.
 * </p>
 *
 * @see OperationType
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Auditable {

    /** Tipo de operación que representa este método. */
    OperationType operationType();

    /** Nombre del módulo funcional al que pertenece la operación. */
    String moduleName() default "CONFIGURATION";

    /** Tabla o entidad lógica afectada por la operación. */
    String affectedTable();
}
