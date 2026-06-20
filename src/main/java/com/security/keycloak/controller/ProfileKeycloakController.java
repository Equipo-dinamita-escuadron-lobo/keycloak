package com.security.keycloak.controller;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.security.keycloak.dtos.ProfileDTO;
import com.security.keycloak.service.IProfileKeycloakService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import jakarta.validation.Valid;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequiredArgsConstructor
@PreAuthorize("hasRole('admin_client')")
@RequestMapping("/api/keycloak/profile")
public class ProfileKeycloakController {

    private final IProfileKeycloakService profileKeycloakService;

    @Operation(summary = "Listar todos los perfiles")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Perfiles encontrados"),
        @ApiResponse(responseCode = "204", description = "No se encontraron perfiles"),
        @ApiResponse(responseCode = "403", description = "No autorizado para acceder a este recurso"),
        @ApiResponse(responseCode = "500", description = "Error interno del servidor")
    })
    @GetMapping("/findAll")
    public ResponseEntity<List<ProfileDTO>> findAllProfiles() {
        log.info("Solicitando todos los perfiles");
        List<ProfileDTO> profiles = profileKeycloakService.findAllProfiles();
        
        if (profiles.isEmpty()) {
            return ResponseEntity.noContent().build();
        }
        
        return ResponseEntity.ok(profiles);
    }

    @Operation(summary = "Buscar perfil por ID")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Perfil encontrado"),
        @ApiResponse(responseCode = "404", description = "No se encontró el perfil"),
        @ApiResponse(responseCode = "403", description = "No autorizado para acceder a este recurso"),
        @ApiResponse(responseCode = "500", description = "Error interno del servidor")
    })
    @GetMapping("/findById/{profileId}")
    public ResponseEntity<ProfileDTO> findProfileById(@PathVariable String profileId) {
        log.debug("Buscando perfil con ID: {}", profileId);
        return ResponseEntity.ok(profileKeycloakService.findProfileById(profileId));
    }

    @Operation(summary = "Buscar perfil por nombre")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Perfiles encontrados"),
        @ApiResponse(responseCode = "204", description = "No se encontraron perfiles"),
        @ApiResponse(responseCode = "403", description = "No autorizado para acceder a este recurso"),
        @ApiResponse(responseCode = "500", description = "Error interno del servidor")
    })
    @GetMapping("/findByName/{profileName}")
    public ResponseEntity<List<ProfileDTO>> findProfileByName(@PathVariable String profileName) {
        log.debug("Buscando perfiles con nombre: {}", profileName);
        List<ProfileDTO> profiles = profileKeycloakService.findProfilesByName(profileName);
        
        if (profiles.isEmpty()) {
            return ResponseEntity.noContent().build();
        }
        
        return ResponseEntity.ok(profiles);
    }

    @Operation(summary = "Crear un nuevo perfil")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "201", description = "Perfil creado exitosamente"),
        @ApiResponse(responseCode = "400", description = "Datos del perfil inválidos"),
        @ApiResponse(responseCode = "409", description = "El nombre del perfil ya existe"),
        @ApiResponse(responseCode = "403", description = "No autorizado para realizar esta operación"),
        @ApiResponse(responseCode = "500", description = "Error interno del servidor")
    })
    @PostMapping("/create")
    public ResponseEntity<ProfileDTO> createProfile(@Valid @RequestBody ProfileDTO profileDTO) {
        log.info("Creando nuevo perfil: {}", profileDTO.getName());
        ProfileDTO createdProfile = profileKeycloakService.createProfile(profileDTO);
        return ResponseEntity.status(HttpStatus.CREATED).body(createdProfile);
    }

    @Operation(summary = "Actualizar perfil por ID")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Perfil actualizado exitosamente"),
        @ApiResponse(responseCode = "400", description = "Datos del perfil inválidos"),
        @ApiResponse(responseCode = "404", description = "No se encontró el perfil"),
        @ApiResponse(responseCode = "409", description = "El nombre del perfil ya existe"),
        @ApiResponse(responseCode = "403", description = "No autorizado para realizar esta operación"),
        @ApiResponse(responseCode = "500", description = "Error interno del servidor")
    })
    @PutMapping("/update/{profileId}")
    public ResponseEntity<ProfileDTO> updateProfile(@PathVariable String profileId,
            @Valid @RequestBody ProfileDTO profileDTO) {
        log.info("Actualizando perfil con ID: {}", profileId);
        return ResponseEntity.ok(profileKeycloakService.updateProfile(profileId, profileDTO));
    }

    @Operation(summary = "Eliminar perfil por ID")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "204", description = "Perfil eliminado exitosamente"),
        @ApiResponse(responseCode = "404", description = "No se encontró el perfil"),
        @ApiResponse(responseCode = "409", description = "El perfil está asignado a uno o más usuarios"),
        @ApiResponse(responseCode = "403", description = "No autorizado para realizar esta operación"),
        @ApiResponse(responseCode = "500", description = "Error interno del servidor")
    })
    @DeleteMapping("/delete/{profileId}")
    public ResponseEntity<Void> deleteProfile(@PathVariable String profileId) {
        log.info("Eliminando perfil con ID: {}", profileId);
        profileKeycloakService.deleteProfile(profileId);
        return ResponseEntity.noContent().build();
    }
}