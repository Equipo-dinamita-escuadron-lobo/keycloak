package com.security.keycloak.controller;

import com.security.keycloak.service.IPasswordRecoveryService;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/keycloak")
@RequiredArgsConstructor
@Validated
public class RecoveryController {

  private final IPasswordRecoveryService recoveryService;

  @PostMapping(value = "/forgot-password", consumes = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<Void> forgot(@RequestBody @Validated EmailDTO req) {
    recoveryService.startRecovery(req.getEmail().trim());
    return ResponseEntity.accepted().build();
  }

  @PostMapping(value = "/reset-password", consumes = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<Void> reset(@RequestBody @Validated ResetDTO req) {
    recoveryService.resetPassword(req.getToken().trim(), req.getNewPassword());
    return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
  }

  @Data
  static class EmailDTO { @NotBlank @Email private String email; }

  @Data
  static class ResetDTO {
    @NotBlank private String token;
    @NotBlank @Size(min = 8, max = 64) private String newPassword;
  }
}
