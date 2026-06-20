package com.security.keycloak.service.impl;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.keycloak.audit.annotation.Auditable;
import com.security.keycloak.audit.annotation.OperationType;
import com.security.keycloak.controller.exception.ConflictException;
import com.security.keycloak.controller.exception.ResourceNotFoundException;
import com.security.keycloak.service.IPermissionKeycloakService;
import com.security.keycloak.util.KeycloakProvider;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Implementación del servicio de permisos para Keycloak.
 * <p>
 * Ofrece operaciones para listar permisos, asociar políticas a permisos,
 * obtener el mapeo de roles con sus permisos y actualizar los permisos
 * de un rol específico. Se integra con los endpoints de administración
 * de Keycloak mediante {@link RestTemplate}.
 * </p>
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class PermissionKeycloakServiceImpl implements IPermissionKeycloakService {

    @Value("${keycloak.realm.name}")
    private String REALM;

    @Value("${keycloak.client.id}")
    private String CLIENT_ID;

    private String ADMIN_REALM_URL;
    private String RESOURCE_SERVER_URL;
    private String RESOURCE_SERVER_SETTINGS_URL;
    private String PERMISSIONS_LIST_URL;
    private String POLICY_ROLE_URL;
    private String PERMISSION_BY_ID_URL_TEMPLATE;
    private String ROLES_URL;
    private String ROLE_BY_NAME_URL;

    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();

    private final KeycloakProvider keycloakProvider;

    /**
     * Inicializa las URLs base utilizadas para invocar la API de administración de
     * Keycloak.
     * <p>
     * Se ejecuta automáticamente después de la inyección de dependencias.
     * </p>
     */
    @PostConstruct
    public void init() {
        this.ADMIN_REALM_URL = "http://contables.unicauca.edu.co/auth/admin/realms/" + REALM;
        this.RESOURCE_SERVER_URL = ADMIN_REALM_URL + "/clients/" + CLIENT_ID + "/authz/resource-server";
        this.RESOURCE_SERVER_SETTINGS_URL = RESOURCE_SERVER_URL + "/settings";
        this.PERMISSIONS_LIST_URL = RESOURCE_SERVER_URL + "/permission";
        this.POLICY_ROLE_URL = RESOURCE_SERVER_URL + "/policy/role";
        this.PERMISSION_BY_ID_URL_TEMPLATE = RESOURCE_SERVER_URL + "/permission/%s";
        this.ROLES_URL = ADMIN_REALM_URL + "/roles";
        this.ROLE_BY_NAME_URL = ROLES_URL + "/%s";
    }

    /**
     * Obtiene todos los permisos del servidor de recursos, excluyendo el permiso
     * por defecto.
     *
     * @return lista de nombres de permisos.
     * @throws RuntimeException si ocurre un error al consultar o procesar la
     *                          respuesta.
     */
    @Override
    public List<String> findAllPermissions() {
        List<String> permissionNames = new ArrayList<>();
        final String DEFAULT_PERMISSION = "Default Permission";

        try {
            HttpHeaders headers = createAuthHeaders();
            HttpEntity<Void> entity = new HttpEntity<>(headers);

            ResponseEntity<String> response = restTemplate.exchange(
                    PERMISSIONS_LIST_URL,
                    HttpMethod.GET,
                    entity,
                    String.class);

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                JsonNode permissionsArray = objectMapper.readTree(response.getBody());

                if (permissionsArray.isArray()) {
                    for (JsonNode permission : permissionsArray) {
                        JsonNode nameNode = permission.get("name");
                        if (nameNode != null && !nameNode.isNull()) {
                            String name = nameNode.asText();
                            if (!DEFAULT_PERMISSION.equals(name)) {
                                permissionNames.add(name);
                            }
                        }
                    }
                }
            } else {
                log.warn("Error obteniendo permisos. Código: {}", response.getStatusCode());
            }
        } catch (Exception e) {
            log.error("Error al listar permisos: {}", e.getMessage(), e);
            throw new RuntimeException("Error interno al recuperar los permisos", e);
        }

        return permissionNames;
    }

    /**
     * Crea (si no existe) una política de rol y la asocia a los permisos indicados.
     *
     * @param permissions lista de nombres de permisos a actualizar.
     * @param roleName    nombre del rol que se usará para crear/nombrar la
     *                    política.
     * @return {@code true} si el proceso finaliza sin errores.
     * @throws ResourceNotFoundException si no se encuentra el rol o un permiso.
     * @throws ConflictException         si Keycloak reporta conflicto al
     *                                   actualizar.
     * @throws RuntimeException          ante otros errores HTTP o internos.
     */
    @Override
    @Auditable(operationType = OperationType.CREATE, affectedTable = "PERMISSION")
    public boolean addPolicytoPermissions(List<String> permissions, String roleName) {
        String newPolicyName = roleName + " Policy";

        if (!createRolePolicy(roleName)) {
            log.error("No se pudo crear la política para el rol: {}", roleName);
            throw new ResourceNotFoundException("Rol no encontrado: " + roleName);
        }

        boolean allSuccessful = true;

        for (String permissionName : permissions) {
            try {
                List<String> currentPolicies = getPoliciesByPermissionName(permissionName);
                if (!currentPolicies.contains(newPolicyName)) {
                    currentPolicies.add(newPolicyName);
                }

                updatePermissionWithPolicies(permissionName, currentPolicies);

            } catch (ResourceNotFoundException | ConflictException ex) {
                throw ex;
            } catch (org.springframework.web.client.HttpClientErrorException e) {
                int sc = e.getStatusCode().value();
                log.error("HTTP {} al actualizar permiso '{}' con política '{}': {}", sc, permissionName, newPolicyName,
                        e.getResponseBodyAsString());
                if (sc == 404)
                    throw new ResourceNotFoundException("Permiso no encontrado: " + permissionName);
                if (sc == 409)
                    throw new ConflictException("Conflicto al actualizar permiso: " + permissionName);
                throw new RuntimeException("Error HTTP al actualizar permiso", e);
            } catch (Exception e) {
                log.error("Error al actualizar el permiso '{}' con la política '{}': {}",
                        permissionName, newPolicyName, e.getMessage(), e);
                throw new RuntimeException("Error interno al asignar política a permisos", e);
            }
        }

        return allSuccessful;
    }

    /**
     * Construye un mapa de roles y sus permisos asociados leyendo la configuración
     * del
     * resource-server del cliente configurado.
     *
     * @return mapa donde la clave es el nombre del rol y el valor es la lista de
     *         permisos.
     * @throws RuntimeException si ocurre un error durante el proceso.
     */
    @Override
    public Map<String, List<String>> getRolesWithPermissions() {
        Map<String, List<String>> result = new HashMap<>();

        try {
            HttpHeaders headers = createAuthHeaders();
            HttpEntity<Void> entity = new HttpEntity<>(headers);

            ResponseEntity<String> response = restTemplate.exchange(
                    RESOURCE_SERVER_SETTINGS_URL,
                    HttpMethod.GET,
                    entity,
                    String.class);

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                JsonNode root = objectMapper.readTree(response.getBody());
                JsonNode policiesNode = root.get("policies");

                if (policiesNode != null && policiesNode.isArray()) {

                    Map<String, String> policyTypeByName = new HashMap<>();
                    for (JsonNode p : policiesNode) {
                        String name = p.path("name").asText(null);
                        String type = p.path("type").asText(null);
                        if (name != null) {
                            policyTypeByName.put(name, type);
                        }
                    }

                    for (JsonNode policy : policiesNode) {
                        if (!"scope".equals(policy.path("type").asText()))
                            continue;

                        String permissionName = policy.path("name").asText();
                        if ("Default Permission".equals(permissionName))
                            continue;

                        JsonNode configNode = policy.path("config");
                        if (configNode.isMissingNode())
                            continue;

                        String applyPoliciesJson = configNode.path("applyPolicies").asText("[]");
                        JsonNode applyPoliciesArray = objectMapper.readTree(applyPoliciesJson);

                        if (applyPoliciesArray.isArray()) {
                            for (JsonNode policyNameNode : applyPoliciesArray) {
                                String policyName = policyNameNode.asText();

                                if (!"role".equals(policyTypeByName.get(policyName)))
                                    continue;

                                String roleName = policyName.endsWith(" Policy")
                                        ? policyName.substring(0, policyName.length() - " Policy".length())
                                        : policyName;

                                List<String> perms = result.computeIfAbsent(roleName, k -> new ArrayList<>());
                                if (!perms.contains(permissionName)) {
                                    perms.add(permissionName);
                                }
                            }
                        }
                    }
                } else {
                    log.warn("No se encontraron 'policies' en settings del resource-server.");
                }
            } else {
                log.warn("No se pudo obtener settings del resource-server. Status: {}", response.getStatusCode());
            }

        } catch (Exception e) {
            log.error("Error al construir el mapa Rol→Permisos: {}", e.getMessage(), e);
            throw new RuntimeException("Error interno al recuperar roles con permisos", e);
        }

        return result;
    }

    /**
     * Actualiza el conjunto de permisos asociados a un rol: agrega los nuevos
     * y elimina los que ya no deben estar vinculados.
     *
     * @param newPermissions lista completa de permisos objetivo para el rol.
     * @param roleName       nombre del rol a actualizar.
     * @return {@code true} si el proceso finaliza sin errores.
     * @throws ResourceNotFoundException si no existe el rol o un permiso.
     * @throws ConflictException         si Keycloak reporta conflicto en la
     *                                   actualización.
     * @throws RuntimeException          para otros errores HTTP o internos.
     */
    @Override
    @Auditable(operationType = OperationType.CREATE, affectedTable = "PERMISSION")
    public boolean updatePermissionsForRole(List<String> newPermissions, String roleName) {
        String roleId = findRoleIdByName(roleName);
        if (roleId == null) {
            throw new ResourceNotFoundException("Rol no encontrado: " + roleName);
        }

        String policyName = roleName + " Policy";
        boolean allSuccessful = true;

        try {
            Map<String, List<String>> rolesWithPerms = getRolesWithPermissions();
            List<String> currentPermissions = rolesWithPerms.getOrDefault(roleName, new ArrayList<>());

            List<String> toAdd = new ArrayList<>(newPermissions);
            toAdd.removeAll(currentPermissions);

            List<String> toRemove = new ArrayList<>(currentPermissions);
            toRemove.removeAll(newPermissions);

            log.info("Permisos a agregar para {}: {}", roleName, toAdd);
            log.info("Permisos a quitar para {}: {}", roleName, toRemove);

            for (String permissionName : toAdd) {
                try {
                    List<String> currentPolicies = getPoliciesByPermissionName(permissionName);
                    if (!currentPolicies.contains(policyName)) {
                        currentPolicies.add(policyName);
                    }
                    updatePermissionWithPolicies(permissionName, currentPolicies);
                } catch (ResourceNotFoundException | ConflictException ex) {
                    throw ex;
                } catch (org.springframework.web.client.HttpClientErrorException e) {
                    int sc = e.getStatusCode().value();
                    log.error("HTTP {} al asignar permiso {} a {}: {}", sc, permissionName, roleName,
                            e.getResponseBodyAsString());
                    if (sc == 404)
                        throw new ResourceNotFoundException("Permiso no encontrado: " + permissionName);
                    if (sc == 409)
                        throw new ConflictException("Conflicto al asignar permiso: " + permissionName);
                    throw new RuntimeException("Error HTTP al asignar permiso", e);
                } catch (Exception e) {
                    log.error("Error al asignar permiso {} a {}: {}", permissionName, roleName, e.getMessage());
                    throw new RuntimeException("Error interno al asignar permiso", e);
                }
            }

            for (String permissionName : toRemove) {
                try {
                    List<String> currentPolicies = getPoliciesByPermissionName(permissionName);
                    if (currentPolicies.contains(policyName)) {
                        currentPolicies.remove(policyName);
                    }
                    updatePermissionWithPolicies(permissionName, currentPolicies);
                } catch (ResourceNotFoundException | ConflictException ex) {
                    throw ex;
                } catch (org.springframework.web.client.HttpClientErrorException e) {
                    int sc = e.getStatusCode().value();
                    log.error("HTTP {} al quitar permiso {} de {}: {}", sc, permissionName, roleName,
                            e.getResponseBodyAsString());
                    if (sc == 404)
                        throw new ResourceNotFoundException("Permiso no encontrado: " + permissionName);
                    if (sc == 409)
                        throw new ConflictException("Conflicto al quitar permiso: " + permissionName);
                    throw new RuntimeException("Error HTTP al quitar permiso", e);
                } catch (Exception e) {
                    log.error("Error al quitar permiso {} de {}: {}", permissionName, roleName, e.getMessage());
                    throw new RuntimeException("Error interno al quitar permiso", e);
                }
            }

        } catch (ResourceNotFoundException | ConflictException ex) {
            throw ex;
        } catch (Exception e) {
            log.error("Error actualizando permisos de {}: {}", roleName, e.getMessage(), e);
            throw new RuntimeException("Error interno al actualizar permisos del rol", e);
        }

        return allSuccessful;
    }

    /**
     * Actualiza un permiso con el listado de políticas aplicables.
     *
     * @param permissionName nombre del permiso a actualizar.
     * @param policies       lista de nombres de políticas a aplicar.
     * @throws ResourceNotFoundException si el permiso no existe.
     * @throws ConflictException         si ocurre un conflicto al actualizar.
     * @throws Exception                 para errores de serialización o HTTP no
     *                                   controlados.
     */
    private void updatePermissionWithPolicies(String permissionName, List<String> policies) throws Exception {
        String permissionId = findPermissionIdByName(permissionName);
        if (permissionId == null) {
            log.warn("No se encontró el ID para el permiso '{}'. Se omite.", permissionName);
            throw new ResourceNotFoundException("Permiso no encontrado: " + permissionName);
        }

        String permUrl = String.format(PERMISSION_BY_ID_URL_TEMPLATE, permissionId);

        HttpHeaders headersGet = createAuthHeaders();
        HttpEntity<Void> getEntity = new HttpEntity<>(headersGet);
        ResponseEntity<String> getResp = restTemplate.exchange(permUrl, HttpMethod.GET, getEntity, String.class);

        if (getResp.getStatusCode() != HttpStatus.OK || getResp.getBody() == null) {
            log.error("No se pudo leer la permission '{}' (id={}). Status={}", permissionName, permissionId,
                    getResp.getStatusCode());
            throw new RuntimeException("No se pudo leer la permission antes de actualizar");
        }

        JsonNode current = objectMapper.readTree(getResp.getBody());
        @SuppressWarnings("unchecked")
        Map<String, Object> fullPayload = objectMapper.convertValue(current, Map.class);

        fullPayload.put("name", permissionName);

        fullPayload.put("policies", policies);

        fullPayload.put("decisionStrategy", "AFFIRMATIVE");

        String jsonBody = objectMapper.writeValueAsString(fullPayload);
        HttpHeaders headersPut = createJsonAuthHeaders();
        HttpEntity<String> putEntity = new HttpEntity<>(jsonBody, headersPut);

        try {
            restTemplate.exchange(permUrl, HttpMethod.PUT, putEntity, Void.class);
            log.info("Permission '{}' actualizada. policies={}, decisionStrategy=AFFIRMATIVE", permissionName,
                    policies.size());
        } catch (org.springframework.web.client.HttpClientErrorException e) {
            int code = e.getStatusCode().value();
            log.error("Error HTTP al actualizar permiso '{}': {} - {}", permissionName, code,
                    e.getResponseBodyAsString());
            if (code == 404)
                throw new ResourceNotFoundException("Permiso no encontrado: " + permissionName);
            if (code == 409)
                throw new ConflictException("Conflicto al actualizar permiso: " + permissionName);
            throw e;
        }
    }

    /**
     * Obtiene los nombres de políticas asociadas a un permiso.
     *
     * @param permissionName nombre del permiso.
     * @return lista de nombres de políticas asociadas (posiblemente vacía).
     * @throws RuntimeException si ocurre un error al consultar o procesar la
     *                          respuesta.
     */
    public List<String> getPoliciesByPermissionName(String permissionName) {
        List<String> policies = new ArrayList<>();

        try {
            HttpHeaders headers = createAuthHeaders();
            HttpEntity<String> entity = new HttpEntity<>(headers);

            ResponseEntity<String> response = restTemplate.exchange(
                    RESOURCE_SERVER_SETTINGS_URL,
                    HttpMethod.GET,
                    entity,
                    String.class);

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                JsonNode root = objectMapper.readTree(response.getBody());
                JsonNode policiesNode = root.get("policies");

                if (policiesNode != null && policiesNode.isArray()) {
                    for (JsonNode policy : policiesNode) {
                        if ("scope".equals(policy.path("type").asText()) &&
                                permissionName.equals(policy.path("name").asText())) {

                            JsonNode configNode = policy.path("config");
                            if (configNode == null || configNode.isMissingNode()) {
                                log.info("El permiso '{}' no tiene configuración de políticas", permissionName);
                                return policies;
                            }

                            String applyPoliciesJson = configNode.path("applyPolicies").asText("[]");
                            JsonNode applyPoliciesArray = objectMapper.readTree(applyPoliciesJson);

                            if (applyPoliciesArray.isArray()) {
                                for (JsonNode policyName : applyPoliciesArray) {
                                    policies.add(policyName.asText());
                                }
                            }
                            return policies;
                        }
                    }
                }
            } else {
                log.warn("No se pudo obtener la configuración del resource-server, status: {}",
                        response.getStatusCode());
            }
        } catch (Exception e) {
            log.error("Error al obtener las políticas del permiso {}: {}", permissionName, e.getMessage(), e);
            throw new RuntimeException("Error interno al consultar políticas del permiso", e);
        }

        return policies;
    }

    /**
     * Busca el ID interno de un permiso a partir de su nombre.
     *
     * @param permissionName nombre del permiso.
     * @return ID del permiso o {@code null} si no se encuentra.
     * @throws RuntimeException si ocurre un error de consulta o parseo.
     */
    private String findPermissionIdByName(String permissionName) {
        try {
            HttpHeaders headers = createAuthHeaders();
            HttpEntity<Void> entity = new HttpEntity<>(headers);

            ResponseEntity<String> response = restTemplate.exchange(
                    PERMISSIONS_LIST_URL,
                    HttpMethod.GET,
                    entity,
                    String.class);

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                JsonNode root = objectMapper.readTree(response.getBody());
                if (root.isArray()) {
                    for (JsonNode permission : root) {
                        if (permissionName.equals(permission.get("name").asText())) {
                            return permission.get("id").asText();
                        }
                    }
                }
            } else {
                log.warn("No se pudo obtener la lista de permisos, status: {}", response.getStatusCode());
            }
        } catch (Exception e) {
            log.error("Error al buscar el ID del permiso '{}': {}", permissionName, e.getMessage(), e);
            throw new RuntimeException("Error interno al buscar permiso", e);
        }

        return null;
    }

    /**
     * Crea una política de tipo rol para el nombre de rol indicado (si no existe).
     *
     * @param roleName nombre del rol.
     * @return {@code true} si la política existe o se crea correctamente;
     *         {@code false} si no se encuentra el rol.
     * @throws RuntimeException ante errores HTTP distintos de 409 o errores
     *                          internos.
     */
    public boolean createRolePolicy(String roleName) {
        String policyName = roleName + " Policy";
        String roleId = findRoleIdByName(roleName);

        if (roleId == null) {
            log.error("No se encontró el rol con nombre: {}", roleName);

            return false;
        }

        try {
            Map<String, Object> payload = new HashMap<>();
            payload.put("name", policyName);
            payload.put("type", "role");
            payload.put("logic", "POSITIVE");

            List<Map<String, String>> rolesList = new ArrayList<>();
            Map<String, String> roleConfig = new HashMap<>();
            roleConfig.put("id", roleId);
            roleConfig.put("required", "true");
            rolesList.add(roleConfig);

            payload.put("roles", rolesList);

            String jsonBody = objectMapper.writeValueAsString(payload);
            log.info("JSON para crear política de rol: {}", jsonBody);

            HttpHeaders headers = createJsonAuthHeaders();
            HttpEntity<String> entity = new HttpEntity<>(jsonBody, headers);

            ResponseEntity<Void> response = restTemplate.postForEntity(
                    POLICY_ROLE_URL,
                    entity,
                    Void.class);

            if (response.getStatusCode() == HttpStatus.CREATED) {
                log.info("Política de rol '{}' creada exitosamente", policyName);
                return true;
            } else if (response.getStatusCode() == HttpStatus.CONFLICT) {
                log.info("La política de rol '{}' ya existía (409). Se continúa.", policyName);
                return true;
            } else {
                log.warn("Error al crear política de rol. Código: {}", response.getStatusCode());
                throw new RuntimeException("Error al crear política de rol (" + response.getStatusCode() + ")");
            }
        } catch (org.springframework.web.client.HttpClientErrorException e) {
            int sc = e.getStatusCode().value();
            if (sc == 409) {
                log.info("La política de rol '{}' ya existía (409). Se continúa.", policyName);
                return true;
            }
            log.error("Error HTTP al crear política de rol '{}': {}", policyName, e.getResponseBodyAsString());
            throw new RuntimeException("Error HTTP al crear política de rol", e);
        } catch (Exception e) {
            log.error("Error al crear política de rol: {}", e.getMessage(), e);
            throw new RuntimeException("Error interno al crear política de rol", e);
        }
    }

    /**
     * Busca el ID de un rol por su nombre utilizando el endpoint de roles.
     *
     * @param roleName nombre del rol.
     * @return ID del rol o {@code null} si no se encuentra.
     * @throws RuntimeException si ocurre un error HTTP distinto de 404 o un error
     *                          interno.
     */
    private String findRoleIdByName(String roleName) {
        try {
            String roleUrl = String.format(ROLE_BY_NAME_URL, roleName);

            HttpHeaders headers = createAuthHeaders();
            HttpEntity<Void> entity = new HttpEntity<>(headers);

            ResponseEntity<String> response = restTemplate.exchange(
                    roleUrl,
                    HttpMethod.GET,
                    entity,
                    String.class);

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                JsonNode roleNode = objectMapper.readTree(response.getBody());
                return roleNode.get("id").asText();
            } else {
                log.warn("Rol no encontrado. Status: {}", response.getStatusCode());
                return null;
            }
        } catch (org.springframework.web.client.HttpClientErrorException e) {
            int sc = e.getStatusCode().value();
            if (sc == 404) {
                log.warn("Rol '{}' no encontrado (404).", roleName);
                return null;
            }
            log.error("Error HTTP {} buscando ID del rol '{}': {}", sc, roleName, e.getResponseBodyAsString());
            throw new RuntimeException("Error HTTP al buscar rol", e);
        } catch (Exception e) {
            log.error("Error buscando ID del rol: {}", e.getMessage(), e);
            throw new RuntimeException("Error interno al buscar rol", e);
        }
    }

    /**
     * Desvincula todas las referencias de políticas asociadas a un rol específico.
     *
     * @param roleName nombre del rol cuyas referencias de políticas serán
     *                 desvinculadas.
     * @return {@code true} si la operación fue exitosa, {@code false} en caso
     *         contrario.
     */
    @Override
    public boolean detachPolicyReferencesForRole(String roleName) {
        final String policyName = roleName + " Policy";

        List<String> allPermissions = findAllPermissions();

        for (String permissionName : allPermissions) {
            try {
                List<String> currentPolicies = getPoliciesByPermissionName(permissionName);
                if (currentPolicies.isEmpty())
                    continue;

                boolean removed = currentPolicies.removeIf(p -> policyName.equals(p));
                if (removed) {
                    updatePermissionWithPolicies(permissionName, currentPolicies);
                    log.info("Policy '{}' removida de permission '{}'", policyName, permissionName);
                }
            } catch (ResourceNotFoundException ex) {
                log.warn("Permission '{}' no encontrada al quitar policy '{}'", permissionName, policyName);
            } catch (ConflictException ex) {
                throw ex;
            } catch (Exception ex) {
                log.error("Error al quitar policy '{}' de permission '{}': {}", policyName, permissionName,
                        ex.getMessage(), ex);
                throw new RuntimeException("Error interno al desasignar policy de permissions", ex);
            }
        }
        return true;
    }

    /**
     * Crea cabeceras HTTP con autenticación Bearer a partir del token de
     * administrador.
     *
     * @return cabeceras con autorización.
     */
    private HttpHeaders createAuthHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(keycloakProvider.getAdminAccessToken());
        return headers;
    }

    /**
     * Crea cabeceras HTTP con autenticación y tipo de contenido JSON.
     *
     * @return cabeceras con autorización y {@code Content-Type: application/json}.
     */
    private HttpHeaders createJsonAuthHeaders() {
        HttpHeaders headers = createAuthHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        return headers;
    }
}
