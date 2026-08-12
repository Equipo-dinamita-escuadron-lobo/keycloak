package com.security.keycloak.infraestructure.input.rest.controller;

import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.security.keycloak.application.output.IAuthOutputPort;
import com.security.keycloak.application.output.IKeycloakOutputPort;
import com.security.keycloak.domain.models.User;
import com.security.keycloak.infraestructure.input.rest.data.response.UserResponse;
import com.security.keycloak.infraestructure.input.rest.mapper.IUserRestMapper;
import com.security.keycloak.infraestructure.output.keycloakAdapter.Exception.UserException;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;

@RestController
@PreAuthorize("hasAnyRole('Administrador', 'admin_client')")
@RequestMapping("/keycloak")
@CrossOrigin("*")
public class KeycloakController {

    @Autowired
    private IKeycloakOutputPort keycloakService;

    @Autowired
    private IAuthOutputPort authService;

    @Autowired
    private IUserRestMapper userMapper;

    @Operation(summary = "Obtener todos los usuarios", description = "Recupera una lista de todos los usuarios registrados en el sistema.", responses = {
            @ApiResponse(responseCode = "200", description = "Lista de usuarios recuperada con éxito", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "500", description = "Error interno al recuperar los usuarios", content = @Content(mediaType = "application/json"))
    })
    @GetMapping("/users")
    public ResponseEntity<?> findAllUsers() {
        return ResponseEntity.ok(keycloakService.findAllUsers());
    }

    @Operation(summary = "Obtener un usuario por ID", description = "Recupera los detalles de un usuario específico utilizando su ID.", responses = {
            @ApiResponse(responseCode = "200", description = "Usuario encontrado con éxito", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "404", description = "Usuario no encontrado", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "500", description = "Error interno al buscar el usuario", content = @Content(mediaType = "application/json"))
    })
    @GetMapping("/user/{userId}")
    public ResponseEntity<?> findUserById(@PathVariable String userId) {
        return ResponseEntity.ok(keycloakService.findUserById(userId));
    }

    @Operation(summary = "Buscar un usuario por nombre de usuario", description = "Recupera los detalles de un usuario específico utilizando su nombre de usuario.", responses = {
            @ApiResponse(responseCode = "200", description = "Usuario encontrado con éxito", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "404", description = "Usuario no encontrado", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "500", description = "Error interno al buscar el usuario", content = @Content(mediaType = "application/json"))
    })
    @GetMapping("/users/{username}")
    public ResponseEntity<?> findUserByUsername(@PathVariable String username) {
        return ResponseEntity.ok(keycloakService.findUserByUsername(username));
    }

    @Operation(summary = "Crear un nuevo usuario", description = "Crea un usuario en el sistema utilizando la información proporcionada en el cuerpo de la solicitud.", responses = {
            @ApiResponse(responseCode = "200", description = "Usuario creado con éxito", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "409", description = "Usuario ya existente", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "400", description = "Solicitud inválida", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "500", description = "Error interno al crear el usuario", content = @Content(mediaType = "application/json"))
    })
    @PostMapping("/create")
    public ResponseEntity<?> createUser(@RequestBody User userDTO) throws URISyntaxException {
        try {
            User response = keycloakService.createUser(userDTO);
            return ResponseEntity.ok(response);
        } catch (UserException e) {
            if (e.getStatus() == 409) {
                return ResponseEntity.status(409).body(e.getMessage());
            } else {
                return ResponseEntity.status(500).body(e.getMessage());
            }
        }
    }

    @Operation(summary = "Actualizar un usuario", description = "Actualiza la información de un usuario existente identificado por su ID.", responses = {
            @ApiResponse(responseCode = "200", description = "Usuario actualizado con éxito", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "404", description = "Usuario no encontrado", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "400", description = "Solicitud inválida", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "500", description = "Error interno del servidor", content = @Content(mediaType = "application/json"))
    })
    @PutMapping("/update/{userId}")
    public ResponseEntity<?> updateUser(@PathVariable String userId, @RequestBody User userDTO) {
        return ResponseEntity.ok(keycloakService.updateUser(userId, userDTO));
    }

    @Operation(summary = "Eliminar un usuario", description = "Elimina un usuario del sistema identificado por su ID.", responses = {
            @ApiResponse(responseCode = "200", description = "Usuario eliminado con éxito", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "404", description = "Usuario no encontrado", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "500", description = "Error interno del servidor", content = @Content(mediaType = "application/json"))
    })
    @DeleteMapping("/delete/{userId}")
    public ResponseEntity<?> deleteUser(@PathVariable String userId) {
        keycloakService.deleteUser(userId);
        return ResponseEntity.ok("User deleted successfully");
    }

    @Operation(summary = "Obtener información del usuario actual", description = "Recupera los detalles del usuario autenticado utilizando el token de autorización proporcionado en el encabezado.", responses = {
            @ApiResponse(responseCode = "200", description = "Información del usuario recuperada con éxito", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "401", description = "No autorizado o token inválido", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "500", description = "Error interno al recuperar la información del usuario", content = @Content(mediaType = "application/json"))
    })
    @PreAuthorize("hasAnyRole('Estudiante', 'Profesor', 'Administrador', 'Invitado', 'user_client', 'admin_client')")
    @GetMapping("/getCurrentUser")
    public UserResponse obtenerUsername(@RequestHeader("Authorization") String authorizationHeader)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        return userMapper.toUserResponse(authService.getCurrentUser(authorizationHeader));
    }

}
