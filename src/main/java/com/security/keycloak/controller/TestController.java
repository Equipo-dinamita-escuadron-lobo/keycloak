package com.security.keycloak.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;

@RestController
@RequestMapping("/api/keycloak/test")
public class TestController {

    @Operation(summary = "Prueba para administradores", description = "Endpoint de prueba accesible únicamente para usuarios con el rol de administrador.", responses = {
            @ApiResponse(responseCode = "200", description = "Acceso permitido. Respuesta de prueba exitosa", content = @Content(mediaType = "text/plain")),
            @ApiResponse(responseCode = "403", description = "Acceso denegado. El usuario no tiene el rol requerido", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "401", description = "No autorizado o token inválido", content = @Content(mediaType = "application/json"))
    })
    @PreAuthorize("hasRole('admin_client')")
    @GetMapping("/testAdmin")

    public String test() {
        return "Test for Admin";
    }

    @Operation(summary = "Prueba para usuarios y administradores", description = "Endpoint de prueba accesible para usuarios con roles de 'user_client' o 'admin_client'.", responses = {
            @ApiResponse(responseCode = "200", description = "Acceso permitido. Respuesta de prueba exitosa", content = @Content(mediaType = "text/plain")),
            @ApiResponse(responseCode = "403", description = "Acceso denegado. El usuario no tiene los roles requeridos", content = @Content(mediaType = "application/json")),
            @ApiResponse(responseCode = "401", description = "No autorizado o token inválido", content = @Content(mediaType = "application/json"))
    })
    @PreAuthorize("hasRole('user_client') or hasRole('admin_client')")
    @GetMapping("/testUser")
    public String testUser() {
        return "Test for User";
    }


    @Operation(
        summary = "Prueba básica de conectividad",
        description = "Este endpoint sirve para verificar la disponibilidad del servidor. Responde con un 'pong' para confirmar que el servidor está activo.",
        responses = {
            @ApiResponse(responseCode = "200", description = "Servidor disponible", content = @Content(mediaType = "text/plain"))
        }
    )
    @GetMapping("/ping")
    public String ping() {
        return "pong";
    }

}
