package com.security.keycloak.controller;

import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.security.keycloak.dtos.UserDTO;
import com.security.keycloak.service.IAuthKeycloakService;
import com.security.keycloak.service.IUserKeycloakService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/keycloak")
public class UserKeycloakController {

    @Autowired
    private IUserKeycloakService userKeycloakService;

    @Autowired
    private IAuthKeycloakService authKeycloakService;

    @Operation(summary = "Obtener todos los usuarios", description = "Recupera una lista de todos los usuarios registrados en el sistema.", responses = {
            @ApiResponse(responseCode = "200", description = "Lista de usuarios recuperada con éxito", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "500", description = "Error interno al recuperar los usuarios", content = @Content(mediaType = "application/json"))
    })
    @GetMapping("/users")
    @PreAuthorize("hasRole('admin_client')")
    public ResponseEntity<?> findAllUsers() {
        return ResponseEntity.ok(userKeycloakService.findAllUsers());
    }

    @Operation(summary = "Obtener un usuario por ID", description = "Recupera los detalles de un usuario específico utilizando su ID.", responses = {
            @ApiResponse(responseCode = "200", description = "Usuario encontrado con éxito", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "404", description = "Usuario no encontrado", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "500", description = "Error interno al buscar el usuario", content = @Content(mediaType = "application/json"))
    })
    @GetMapping("/user/{userId}")
    @PreAuthorize("hasRole('admin_client')")
    public ResponseEntity<?> findUserById(@PathVariable String userId) {
        return ResponseEntity.ok(userKeycloakService.findUserById(userId));
    }

    @Operation(summary = "Buscar usuarios por email", description = "Recupera usuarios que coincidan exactamente con el email proporcionado.", responses = {
            @ApiResponse(responseCode = "200", description = "Usuarios encontrados", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "204", description = "No se encontraron usuarios con ese email"),
            @ApiResponse(responseCode = "403", description = "No autorizado para acceder a este recurso"),
            @ApiResponse(responseCode = "500", description = "Error interno al buscar usuarios", content = @Content(mediaType = "application/json"))
    })
    @GetMapping("/users/{email}")
    @PreAuthorize("hasRole('admin_client')")
    public ResponseEntity<?> findUserByEmail(@PathVariable String email) {
        return ResponseEntity.ok(userKeycloakService.findUserByEmail(email));
    }

    @Operation(summary = "Buscar un usuario por nombre de usuario", description = "Recupera los detalles de un usuario específico utilizando su nombre de usuario.", responses = {
            @ApiResponse(responseCode = "200", description = "Usuario encontrado con éxito", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "404", description = "Usuario no encontrado", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "500", description = "Error interno al buscar el usuario", content = @Content(mediaType = "application/json"))
    })
    @GetMapping("/users/{username}")
    @PreAuthorize("hasRole('admin_client')")
    public ResponseEntity<?> findUserByUsername(@PathVariable String username) {
        return ResponseEntity.ok(userKeycloakService.findUserByUsername(username));
    }

    @Operation(summary = "Crear un nuevo usuario", description = "Crea un usuario en el sistema utilizando la información proporcionada en el cuerpo de la solicitud.", responses = {
            @ApiResponse(responseCode = "200", description = "Usuario creado con éxito", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "409", description = "Usuario ya existente", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "400", description = "Solicitud inválida", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "500", description = "Error interno al crear el usuario", content = @Content(mediaType = "application/json"))
    })
    @PostMapping("/create")
    @PreAuthorize("hasRole('admin_client')")
    public ResponseEntity<?> createUser(@Valid @RequestBody UserDTO userDTO) throws URISyntaxException {
        UserDTO response = userKeycloakService.createUser(userDTO, null);
        return ResponseEntity.ok(response);
    }

    @Operation(summary = "Registrar un nuevo usuario", description = "Registra un usuario en el sistema para acceso público.", responses = {
            @ApiResponse(responseCode = "200", description = "Usuario registrado con éxito", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "409", description = "Usuario ya existente", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "400", description = "Solicitud inválida", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "500", description = "Error interno al registrar el usuario", content = @Content(mediaType = "application/json"))
    })
    @PreAuthorize("permitAll()")
    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody UserDTO userDTO) throws URISyntaxException {
        UserDTO response = userKeycloakService.createUser(userDTO, "Estudiante");
        return ResponseEntity.ok(response);
    }

    @Operation(summary = "Actualizar un usuario", description = "Actualiza la información de un usuario existente identificado por su ID.", responses = {
            @ApiResponse(responseCode = "200", description = "Usuario actualizado con éxito", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "404", description = "Usuario no encontrado", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "400", description = "Solicitud inválida", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "500", description = "Error interno del servidor", content = @Content(mediaType = "application/json"))
    })
    @PutMapping("/update/{userId}")
    @PreAuthorize("hasRole('admin_client')")
    public ResponseEntity<?> updateUser(@PathVariable String userId, @Valid @RequestBody UserDTO userDTO) {
        return ResponseEntity.ok(userKeycloakService.updateUser(userId, userDTO));
    }

    @Operation(summary = "Eliminar un usuario", description = "Elimina un usuario del sistema identificado por su ID.", responses = {
            @ApiResponse(responseCode = "200", description = "Usuario eliminado con éxito", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "404", description = "Usuario no encontrado", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "500", description = "Error interno del servidor", content = @Content(mediaType = "application/json"))
    })
    @DeleteMapping("/delete/{userId}")
    @PreAuthorize("hasRole('admin_client')")
    public ResponseEntity<Void> deleteUser(@PathVariable String userId) {
        userKeycloakService.deleteUser(userId);
        return ResponseEntity.noContent().build();
    }

    @Operation(summary = "Obtener información del usuario actual", description = "Recupera los detalles del usuario autenticado utilizando el token de autorización proporcionado en el encabezado.", responses = {
            @ApiResponse(responseCode = "200", description = "Información del usuario recuperada con éxito", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "401", description = "No autorizado o token inválido", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "500", description = "Error interno al recuperar la información del usuario", content = @Content(mediaType = "application/json"))
    })
    @PreAuthorize("hasRole('user_client') or hasRole('admin_client')")
    @GetMapping("/getCurrentUser")
    public UserDTO obtenerUsername(@RequestHeader("Authorization") String authorizationHeader)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        return authKeycloakService.getCurrentUser(authorizationHeader);
    }

    @Operation(summary = "Obtener lista de roles disponibles", description = "Recupera una lista de todos los roles personalizados disponibles en el sistema.", responses = {
            @ApiResponse(responseCode = "200", description = "Lista de roles recuperada con éxito", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "500", description = "Error interno al recuperar los roles", content = @Content(mediaType = "application/json"))
    })
    @GetMapping("/roles")
    @PreAuthorize("hasRole('admin_client')")
    public ResponseEntity<?> getRoles() {
        return ResponseEntity.ok(userKeycloakService.getRoles());
    }

}
