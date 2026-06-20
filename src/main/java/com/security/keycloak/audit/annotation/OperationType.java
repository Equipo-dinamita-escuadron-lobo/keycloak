package com.security.keycloak.audit.annotation;

/**
 * Tipos de operación auditables en el micro de Keycloak.
 */
public enum OperationType {
    CREATE,
    UPDATE,
    DELETE,
    ASSIGN_PERMISSIONS,
    UPDATE_PERMISSIONS,
    RESET_PASSWORD
}
