package com.security.keycloak.service.impl;

import com.security.keycloak.controller.exception.ResourceNotFoundException;
import com.security.keycloak.util.KeycloakProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.*;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Pruebas unitarias para {@link PermissionKeycloakServiceImpl}.
 * <p>
 * <strong>Objetivo:</strong> Validar la lógica de negocio que integra con la API de administración
 * de Keycloak para listar permisos, mapear políticas/roles, crear políticas de rol y actualizar
 * permisos de un rol.
 * </p>
 *
 * <p>
 * <strong>Alcance y consideraciones:</strong>
 * <ul>
 *   <li>Las pruebas <b>no</b> usan contexto de Spring ni arranque de microservicio.</li>
 *   <li>Se mockean {@link RestTemplate} (llamadas HTTP) y {@link KeycloakProvider} (token admin).</li>
 *   <li>Los valores @Value (REALM, CLIENT_ID) y el RestTemplate interno se inyectan por reflexión.</li>
 *   <li>Se cubren rutas felices y mapeos de errores (404 → {@link ResourceNotFoundException},
 *       409 → manejo idempotente, otros 4xx → {@link RuntimeException}).</li>
 *   <li>No se prueban Lombok, mappers ni configuración generada.</li>
 *   <li>Los métodos privados se prueban indirectamente; cuando es necesario, se invocan
 *       por reflexión desempaquetando la excepción para mantener la semántica pública.</li>
 * </ul>
 * </p>
 *
 * <p>
 * <strong>Estrategia:</strong>
 * <ul>
 *   <li>Se stubbean las respuestas HTTP con JSON mínimos (válidos) según cada caso.</li>
 *   <li>Para listas que el servicio modifica (add/remove), los tests devuelven listas
 *       <b>mutables</b> (p.ej., <code>new ArrayList<>(...)</code>).</li>
 *   <li>Cuando hay múltiples llamadas secuenciales al mismo endpoint, se encadenan
 *       <code>thenReturn(...).thenReturn(...)</code> para evitar “heap pollution” por varargs.</li>
 * </ul>
 * </p>
 */
class PermissionKeycloakServiceImplUnitTest {

    private KeycloakProvider keycloakProvider;
    private RestTemplate restTemplateMock;
    private PermissionKeycloakServiceImpl service;

    // URLs calculadas en init() (se replican aquí para facilitar el stubbing)
    private String ADMIN_REALM_URL;
    private String RESOURCE_SERVER_URL;
    private String RESOURCE_SERVER_SETTINGS_URL;
    private String PERMISSIONS_LIST_URL;
    private String POLICY_ROLE_URL;
    private String PERMISSION_BY_ID_URL_TEMPLATE;
    private String ROLES_URL;
    private String ROLE_BY_NAME_URL;

    /**
     * Configura mocks, inyección por reflexión y construye las URLs que usaremos en los stubs.
     */
    @BeforeEach
    void setUp() throws Exception {
        keycloakProvider = mock(KeycloakProvider.class);
        when(keycloakProvider.getAdminAccessToken()).thenReturn("fake-token");

        service = new PermissionKeycloakServiceImpl(keycloakProvider);

        // Inyección manual de @Value y RestTemplate (sin contexto de Spring)
        setField(service, "REALM", "realm-dev");
        setField(service, "CLIENT_ID", "client-123");

        restTemplateMock = mock(RestTemplate.class);
        setField(service, "restTemplate", restTemplateMock);

        // Ejecuta @PostConstruct → arma las URLs
        service.init();

        ADMIN_REALM_URL = "http://contables.unicauca.edu.co/auth/admin/realms/realm-dev";
        RESOURCE_SERVER_URL = ADMIN_REALM_URL + "/clients/client-123/authz/resource-server";
        RESOURCE_SERVER_SETTINGS_URL = RESOURCE_SERVER_URL + "/settings";
        PERMISSIONS_LIST_URL = RESOURCE_SERVER_URL + "/permission";
        POLICY_ROLE_URL = RESOURCE_SERVER_URL + "/policy/role";
        PERMISSION_BY_ID_URL_TEMPLATE = RESOURCE_SERVER_URL + "/permission/%s";
        ROLES_URL = ADMIN_REALM_URL + "/roles";
        ROLE_BY_NAME_URL = ROLES_URL + "/%s";
    }

    // -------------------------------------------------------
    // findAllPermissions
    // -------------------------------------------------------

    /**
     * Debe devolver la lista de permisos excluyendo "Default Permission".
     */
    @Test
    void findAllPermissions_returnsNames_excludingDefault() {
        String json =
                "[" +
                  "{\"id\":\"p1\",\"name\":\"Default Permission\"}," +
                  "{\"id\":\"p2\",\"name\":\"READ_INVOICES\"}," +
                  "{\"id\":\"p3\",\"name\":\"WRITE_USERS\"}" +
                "]";
        when(restTemplateMock.exchange(
                eq(PERMISSIONS_LIST_URL),
                eq(HttpMethod.GET),
                any(HttpEntity.class),
                eq(String.class))
        ).thenReturn(new ResponseEntity<>(json, HttpStatus.OK));

        List<String> out = service.findAllPermissions();

        assertThat(out).containsExactlyInAnyOrder("READ_INVOICES", "WRITE_USERS");
        assertThat(out).doesNotContain("Default Permission");
    }

    /**
     * Si el GET devuelve non-OK, el servicio se limita a registrar y retorna vacío.
     */
    @Test
    void findAllPermissions_nonOK_returnsEmpty() {
        when(restTemplateMock.exchange(
                eq(PERMISSIONS_LIST_URL),
                eq(HttpMethod.GET),
                any(HttpEntity.class),
                eq(String.class))
        ).thenReturn(new ResponseEntity<>("", HttpStatus.SERVICE_UNAVAILABLE));

        List<String> out = service.findAllPermissions();

        assertThat(out).isEmpty();
    }

    /**
     * Si ocurre una excepción, se envuelve en RuntimeException con mensaje amigable.
     */
    @Test
    void findAllPermissions_onException_wrapsRuntime() {
        when(restTemplateMock.exchange(
                anyString(), any(), any(HttpEntity.class), eq(String.class))
        ).thenThrow(new RuntimeException("boom"));

        assertThatThrownBy(() -> service.findAllPermissions())
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Error interno al recuperar los permisos");
    }

    // -------------------------------------------------------
    // getPoliciesByPermissionName
    // -------------------------------------------------------

    /**
     * Debe devolver las políticas aplicadas a un permiso cuando están configuradas.
     */
    @Test
    void getPoliciesByPermissionName_returnsList_whenPresent() {
        String settingsJson = "{ \"policies\": [ " +
                "{\"name\":\"READ_INVOICES\",\"type\":\"resource\",\"config\":{\"applyPolicies\":\"[\\\"Admin Policy\\\",\\\"User Policy\\\"]\"}}, " +
                "{\"name\":\"Admin Policy\",\"type\":\"role\"}, " +
                "{\"name\":\"User Policy\",\"type\":\"role\"} ] }";

        when(restTemplateMock.exchange(
                eq(RESOURCE_SERVER_SETTINGS_URL),
                eq(HttpMethod.GET),
                any(HttpEntity.class),
                eq(String.class))
        ).thenReturn(new ResponseEntity<>(settingsJson, HttpStatus.OK));

        List<String> policies = service.getPoliciesByPermissionName("READ_INVOICES");
        assertThat(policies).containsExactly("Admin Policy", "User Policy");
    }

    /**
     * Si el permiso no existe en policies, retorna lista vacía.
     */
    @Test
    void getPoliciesByPermissionName_returnsEmpty_whenNotFound() {
        String settingsJson = "{ \"policies\": [ {\"name\":\"Other\",\"type\":\"resource\",\"config\":{\"applyPolicies\":\"[]\"}} ] }";

        when(restTemplateMock.exchange(
                eq(RESOURCE_SERVER_SETTINGS_URL),
                eq(HttpMethod.GET),
                any(HttpEntity.class),
                eq(String.class))
        ).thenReturn(new ResponseEntity<>(settingsJson, HttpStatus.OK));

        assertThat(service.getPoliciesByPermissionName("MISSING")).isEmpty();
    }

    /**
     * Ante error en el GET, se envuelve en RuntimeException con mensaje amigable.
     */
    @Test
    void getPoliciesByPermissionName_onError_wrapsRuntime() {
        when(restTemplateMock.exchange(
                eq(RESOURCE_SERVER_SETTINGS_URL),
                eq(HttpMethod.GET),
                any(HttpEntity.class),
                eq(String.class))
        ).thenThrow(new RuntimeException("boom"));

        assertThatThrownBy(() -> service.getPoliciesByPermissionName("X"))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Error interno al consultar políticas del permiso");
    }

    // -------------------------------------------------------
    // updatePermissionWithPolicies (privado) — cubierto por reflexión
    // -------------------------------------------------------

    /**
     * Flujo feliz: encuentra el permiso, obtiene detalle y realiza PUT de actualización.
     */
    @Test
    void updatePermissionWithPolicies_updatesSuccessfully() {
        String permsJson = "[{\"id\":\"p2\",\"name\":\"READ_INVOICES\"}]";
        when(restTemplateMock.exchange(
                eq(PERMISSIONS_LIST_URL), eq(HttpMethod.GET),
                any(HttpEntity.class), eq(String.class))
        ).thenReturn(new ResponseEntity<>(permsJson, HttpStatus.OK));

        String permDetail = "{ \"id\":\"p2\", \"name\":\"READ_INVOICES\", \"config\":{}, \"policies\": [\"Admin Policy\"] }";
        when(restTemplateMock.exchange(
                eq(String.format(PERMISSION_BY_ID_URL_TEMPLATE, "p2")),
                eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class))
        ).thenReturn(new ResponseEntity<>(permDetail, HttpStatus.OK));

        when(restTemplateMock.exchange(
                eq(String.format(PERMISSION_BY_ID_URL_TEMPLATE, "p2")),
                eq(HttpMethod.PUT), any(HttpEntity.class), eq(Void.class))
        ).thenReturn(new ResponseEntity<>(HttpStatus.NO_CONTENT));

        invokeUpdatePermissionWithPolicies(service, "READ_INVOICES", List.of("Admin Policy", "User Policy"));

        verify(restTemplateMock, times(1)).exchange(
                eq(String.format(PERMISSION_BY_ID_URL_TEMPLATE, "p2")),
                eq(HttpMethod.PUT), any(HttpEntity.class), eq(Void.class));
    }

    /**
     * Si el PUT devuelve 404, el servicio mapea a ResourceNotFoundException.
     */
    @Test
    void updatePermissionWithPolicies_maps404_to_ResourceNotFound() {
        String permsJson = "[{\"id\":\"p2\",\"name\":\"READ_INVOICES\"}]";
        when(restTemplateMock.exchange(
                eq(PERMISSIONS_LIST_URL), eq(HttpMethod.GET),
                any(HttpEntity.class), eq(String.class))
        ).thenReturn(new ResponseEntity<>(permsJson, HttpStatus.OK));

        String permDetail = "{ \"id\":\"p2\", \"name\":\"READ_INVOICES\" }";
        when(restTemplateMock.exchange(
                eq(String.format(PERMISSION_BY_ID_URL_TEMPLATE, "p2")),
                eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class))
        ).thenReturn(new ResponseEntity<>(permDetail, HttpStatus.OK));

        doThrow(new HttpClientErrorException(HttpStatus.NOT_FOUND))
                .when(restTemplateMock).exchange(
                        eq(String.format(PERMISSION_BY_ID_URL_TEMPLATE, "p2")),
                        eq(HttpMethod.PUT), any(HttpEntity.class), eq(Void.class));

        assertThatThrownBy(() ->
                invokeUpdatePermissionWithPolicies(service, "READ_INVOICES", List.of("X"))
        ).isInstanceOf(ResourceNotFoundException.class);
    }

    // -------------------------------------------------------
    // createRolePolicy (usa findRoleIdByName indirectamente)
    // -------------------------------------------------------

    /**
     * Si el rol existe (200) y el POST crea (201), retorna true.
     */
    @Test
    void createRolePolicy_creates_whenRoleExists() {
        String roleJson = "{ \"id\":\"r-123\", \"name\":\"admin\" }";
        when(restTemplateMock.exchange(
                eq(String.format(ROLE_BY_NAME_URL, "admin")),
                eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class))
        ).thenReturn(new ResponseEntity<>(roleJson, HttpStatus.OK));

        when(restTemplateMock.postForEntity(
                eq(POLICY_ROLE_URL), any(HttpEntity.class), eq(Void.class))
        ).thenReturn(new ResponseEntity<>(HttpStatus.CREATED));

        boolean ok = service.createRolePolicy("admin");
        assertThat(ok).isTrue();
    }

    /**
     * Si el POST devuelve 409 (ya existía), el servicio lo trata como éxito idempotente.
     */
    @Test
    void createRolePolicy_returnsTrue_onConflict409() {
        String roleJson = "{ \"id\":\"r-123\", \"name\":\"admin\" }";
        when(restTemplateMock.exchange(
                eq(String.format(ROLE_BY_NAME_URL, "admin")),
                eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class))
        ).thenReturn(new ResponseEntity<>(roleJson, HttpStatus.OK));

        when(restTemplateMock.postForEntity(
                eq(POLICY_ROLE_URL), any(HttpEntity.class), eq(Void.class))
        ).thenReturn(new ResponseEntity<>(HttpStatus.CONFLICT));

        assertThat(service.createRolePolicy("admin")).isTrue();
    }

    /**
     * Si el rol no existe (404), createRolePolicy retorna false.
     */
    @Test
    void createRolePolicy_returnsFalse_whenRoleMissing() {
        doThrow(new HttpClientErrorException(HttpStatus.NOT_FOUND))
                .when(restTemplateMock).exchange(
                        eq(String.format(ROLE_BY_NAME_URL, "ghost")),
                        eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class));

        assertThat(service.createRolePolicy("ghost")).isFalse();
    }

    // -------------------------------------------------------
    // getRolesWithPermissions
    // -------------------------------------------------------

    /**
     * Construye correctamente el mapa Rol → [Permisos] usando las policies del resource-server.
     */
    @Test
    void getRolesWithPermissions_buildsMap() {
        String settingsJson = "{ \"policies\": [ " +
                "{\"name\":\"Manager Policy\",\"type\":\"role\"}, " +
                "{\"name\":\"User Policy\",\"type\":\"role\"}, " +
                "{\"name\":\"READ_INVOICES\",\"type\":\"resource\",\"config\":{\"applyPolicies\":\"[\\\"Manager Policy\\\",\\\"User Policy\\\"]\"}} ] }";

        when(restTemplateMock.exchange(
                eq(RESOURCE_SERVER_SETTINGS_URL), eq(HttpMethod.GET),
                any(HttpEntity.class), eq(String.class))
        ).thenReturn(new ResponseEntity<>(settingsJson, HttpStatus.OK));

        Map<String, List<String>> map = service.getRolesWithPermissions();

        assertThat(map).containsKeys("Manager", "User");
        assertThat(map.get("Manager")).containsExactly("READ_INVOICES");
        assertThat(map.get("User")).containsExactly("READ_INVOICES");
    }

    // -------------------------------------------------------
    // updatePermissionsForRole
    // -------------------------------------------------------

    /**
     * Actualizar permisos de un rol: agrega uno nuevo y remueve uno viejo (dos PUTs).
     * Se usa stubbing secuencial para el GET /permission y listas mutables para policies.
     */
    @Test
    void updatePermissionsForRole_addsAndRemoves_ok() {
        String roleJson = "{ \"id\":\"r-77\", \"name\":\"manager\" }";
        when(restTemplateMock.exchange(
                eq(String.format(ROLE_BY_NAME_URL, "manager")),
                eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class))
        ).thenReturn(new ResponseEntity<>(roleJson, HttpStatus.OK));

        PermissionKeycloakServiceImpl spy = Mockito.spy(service);
        setField(spy, "restTemplate", restTemplateMock);

        // Estado actual: OLD_PERM
        doReturn(Map.of("manager", List.of("OLD_PERM")))
                .when(spy).getRolesWithPermissions();

        // Policies (mutables) para ADD y REMOVE
        doReturn(new ArrayList<>(List.of("Manager Policy")))
                .when(spy).getPoliciesByPermissionName("READ_INVOICES");
        doReturn(new ArrayList<>(List.of("Manager Policy")))
                .when(spy).getPoliciesByPermissionName("OLD_PERM");

        // GET /permission (secuencial): primero READ_INVOICES, luego OLD_PERM
        ResponseEntity<String> r1 = new ResponseEntity<>(
                "[{\"id\":\"pid-read\",\"name\":\"READ_INVOICES\"}]", HttpStatus.OK);
        ResponseEntity<String> r2 = new ResponseEntity<>(
                "[{\"id\":\"pid-old\",\"name\":\"OLD_PERM\"}]", HttpStatus.OK);

        when(restTemplateMock.exchange(
                eq(PERMISSIONS_LIST_URL),
                eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class))
        ).thenReturn(r1).thenReturn(r2);

        // GET detalle para ambos ids y PUT de actualización
        String detailRead = "{\"id\":\"pid-read\",\"name\":\"READ_INVOICES\"}";
        String detailOld  = "{\"id\":\"pid-old\",\"name\":\"OLD_PERM\"}";

        when(restTemplateMock.exchange(
                eq(String.format(PERMISSION_BY_ID_URL_TEMPLATE, "pid-read")),
                eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class))
        ).thenReturn(new ResponseEntity<>(detailRead, HttpStatus.OK));

        when(restTemplateMock.exchange(
                eq(String.format(PERMISSION_BY_ID_URL_TEMPLATE, "pid-old")),
                eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class))
        ).thenReturn(new ResponseEntity<>(detailOld, HttpStatus.OK));

        when(restTemplateMock.exchange(
                contains("pid-read"), eq(HttpMethod.PUT),
                any(HttpEntity.class), eq(Void.class))
        ).thenReturn(new ResponseEntity<>(HttpStatus.NO_CONTENT));

        when(restTemplateMock.exchange(
                contains("pid-old"), eq(HttpMethod.PUT),
                any(HttpEntity.class), eq(Void.class))
        ).thenReturn(new ResponseEntity<>(HttpStatus.NO_CONTENT));

        boolean ok = spy.updatePermissionsForRole(List.of("READ_INVOICES"), "manager");
        assertThat(ok).isTrue();

        verify(restTemplateMock, times(1)).exchange(
                contains("pid-read"), eq(HttpMethod.PUT),
                any(HttpEntity.class), eq(Void.class));
        verify(restTemplateMock, times(1)).exchange(
                contains("pid-old"), eq(HttpMethod.PUT),
                any(HttpEntity.class), eq(Void.class));
    }

    // =======================================================
    // Helpers (utilizados para inyección y métodos privados)
    // =======================================================

    /**
     * Inyección por reflexión de un campo privado (sin dependencia del contexto de Spring).
     */
    private static void setField(Object target, String fieldName, Object value) {
        try {
            Field f = target.getClass().getDeclaredField(fieldName);
            f.setAccessible(true);
            f.set(target, value);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Invoca el método privado updatePermissionWithPolicies(nombre, policies) y desempaqueta
     * la InvocationTargetException para exponer la excepción original con la semántica del servicio.
     */
    private static void invokeUpdatePermissionWithPolicies(
            PermissionKeycloakServiceImpl target, String name, List<String> policies) {
        try {
            Method m = PermissionKeycloakServiceImpl.class
                    .getDeclaredMethod("updatePermissionWithPolicies", String.class, List.class);
            m.setAccessible(true);
            m.invoke(target, name, policies);
        } catch (InvocationTargetException ite) {
            Throwable cause = ite.getCause();
            if (cause instanceof RuntimeException re) throw re;
            throw new RuntimeException(cause);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}