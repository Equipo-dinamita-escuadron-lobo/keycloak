package com.security.keycloak.dtos;

import java.util.List;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AddPolicyToPermissionsDTO {

    @NotEmpty(message = "La lista de permisos no puede estar vacía")
    private List<@NotBlank(message = "El nombre del permiso no puede estar vacío") String> permissionNames;

    @NotBlank(message = "El nombre del rol es obligatorio")
    private String roleName;
}