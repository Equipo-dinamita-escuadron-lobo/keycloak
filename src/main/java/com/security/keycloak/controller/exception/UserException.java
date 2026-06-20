package com.security.keycloak.controller.exception;

import lombok.Getter;
import io.swagger.v3.oas.annotations.media.Schema; 

@Getter
public class UserException extends RuntimeException{
    @Schema(description = "Estado", example = "400")
    private int status;

    public UserException(String message, int status) {
        super(message);
        this.status = status;
    } 
}
