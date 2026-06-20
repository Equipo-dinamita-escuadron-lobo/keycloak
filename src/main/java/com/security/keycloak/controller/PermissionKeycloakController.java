package com.security.keycloak.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import com.security.keycloak.dtos.AddPolicyToPermissionsDTO;
import com.security.keycloak.service.IPermissionKeycloakService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.List;
import java.util.Map;

@Slf4j
@RestController
@RequiredArgsConstructor
@PreAuthorize("hasRole('admin_client')")
@RequestMapping("/api/keycloak/permissions")
public class PermissionKeycloakController {

    private final IPermissionKeycloakService permissionKeycloakService;

    @Operation(summary = "Obtener todos los permisos")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Lista de permisos recuperada con éxito"),
        @ApiResponse(responseCode = "403", description = "No autorizado para acceder a este recurso"),
        @ApiResponse(responseCode = "500", description = "Error interno al recuperar los permisos")
    })
    @GetMapping("/findAll")
    public ResponseEntity<List<String>> findAllPermissions() {
        log.info("Solicitando lista de permisos");
        List<String> permissions = permissionKeycloakService.findAllPermissions();

        if (permissions.isEmpty()) {
            return ResponseEntity.noContent().build();
        }
        return ResponseEntity.ok(permissions);
    }

    @Operation(summary = "Agregar política a permisos")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Política agregada con éxito a los permisos"),
        @ApiResponse(responseCode = "400", description = "Datos inválidos en la solicitud"),
        @ApiResponse(responseCode = "404", description = "Permiso o rol no encontrado"),
        @ApiResponse(responseCode = "403", description = "No autorizado para realizar esta operación"),
        @ApiResponse(responseCode = "500", description = "Error interno del servidor")
    })
    @PutMapping("/assignRoleToPermissions")
    public ResponseEntity<String> addPolicyToPermissions(@Valid @RequestBody AddPolicyToPermissionsDTO request) {
        log.info("Asignando rol {} a permisos {}", request.getRoleName(), request.getPermissionNames());
        permissionKeycloakService.addPolicytoPermissions(request.getPermissionNames(), request.getRoleName());
        return ResponseEntity.ok("Permisos asignados con éxito");
    }

    @Operation(summary = "Obtener roles con permisos")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Roles y permisos obtenidos exitosamente"),
        @ApiResponse(responseCode = "403", description = "No autorizado para acceder a este recurso"),
        @ApiResponse(responseCode = "500", description = "Error interno del servidor")
    })
    @GetMapping("/rolesWithPermissions")
    public ResponseEntity<Map<String, List<String>>> getRolesWithPermissions() {
        log.info("Solicitando roles con sus permisos");
        return ResponseEntity.ok(permissionKeycloakService.getRolesWithPermissions());
    }

    @Operation(summary = "Actualizar permisos para un rol")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Permisos actualizados exitosamente para el rol"),
        @ApiResponse(responseCode = "400", description = "Datos inválidos en la solicitud"),
        @ApiResponse(responseCode = "404", description = "Rol no encontrado"),
        @ApiResponse(responseCode = "403", description = "No autorizado para realizar esta operación"),
        @ApiResponse(responseCode = "500", description = "Error interno del servidor")
    })
    @PutMapping("/updatePermissionsForRole")
    public ResponseEntity<String> updatePermissionsForRole(@Valid @RequestBody AddPolicyToPermissionsDTO request) {
        log.info("Actualizando permisos para el rol {}", request.getRoleName());
        permissionKeycloakService.updatePermissionsForRole(request.getPermissionNames(), request.getRoleName());
        return ResponseEntity.ok("Permisos actualizados con éxito");
    }
}
