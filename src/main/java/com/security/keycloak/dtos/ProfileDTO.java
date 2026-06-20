package com.security.keycloak.dtos;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class ProfileDTO {

    private String id; 

    @NotBlank(message = "El nombre es obligatorio")
    @Pattern(
        regexp = "^[\\p{L} ]+$", 
        message = "El nombre solo puede contener letras y espacios"
    )
    private String name;

    @NotBlank(message = "La descripción es obligatoria")
    @Pattern(
        regexp = "^[\\p{L} ]+$", 
        message = "La descripción solo puede contener letras y espacios"
    )
    private String description;
}