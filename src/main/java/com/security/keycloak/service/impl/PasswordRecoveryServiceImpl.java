package com.security.keycloak.service.impl;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.UUID;
import java.util.regex.Pattern;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import com.security.keycloak.controller.exception.ResourceNotFoundException;
import com.security.keycloak.controller.exception.UserException;
import com.security.keycloak.service.IMailService;
import com.security.keycloak.service.IPasswordRecoveryService;
import com.security.keycloak.util.KeycloakProvider;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class PasswordRecoveryServiceImpl implements IPasswordRecoveryService {

  private final StringRedisTemplate redis;
  private final IMailService mail;
  private final KeycloakProvider kc;

  @Value("${app.recovery.ttl-seconds:3600}")
  private long ttl;
  @Value("${app.recovery.base-url}")
  private String baseUrl;
  @Value("${app.jwt.recovery-prefix:pwd:reset:}")
  private String prefix;

  private static final Pattern STRONG_PASSWORD_PATTERN = Pattern
      .compile("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*#?&])[A-Za-z\\d@$!%*#?&]{8,20}$");

  @Override
  public void startRecovery(String email) {
    try {
      // Validar formato de email
      if (email == null || email.isBlank()) {
        throw new UserException("El correo electrónico es obligatorio", 400);
      }

      var user = kc.findUserByEmailOrThrow(email);
      String token = UUID.randomUUID().toString();
      redis.opsForValue().set(prefix + token, user.getId(), Duration.ofSeconds(ttl));
      String link = baseUrl + "?token=" + URLEncoder.encode(token, StandardCharsets.UTF_8);

      mail.send(email, "Recupera tu contraseña", "Haz clic en el siguiente enlace: " + link);

      log.info("Enlace de recuperación de contraseña enviado a: {}", email);
    } catch (ResourceNotFoundException e) {
      // Por seguridad, no revelamos si el email existe o no
      log.warn("Intento de recuperación de contraseña para email no registrado: {}", email);
      // No lanzamos excepción para evitar enumeración de usuarios
    } catch (Exception e) {
      log.error("Error al iniciar recuperación de contraseña para: {}", email, e);
      throw new UserException("Error al procesar la solicitud de recuperación", 500);
    }
  }

  @Override
  public void resetPassword(String token, String newPassword) {
    try {
      // Validar token
      if (token == null || token.isBlank()) {
        throw new UserException("El token de recuperación es obligatorio", 400);
      }

      // Validar nueva contraseña
      if (newPassword == null || newPassword.isBlank()) {
        throw new UserException("La nueva contraseña es obligatoria", 400);
      }

      if (newPassword.length() < 8 || newPassword.length() > 20) {
        throw new UserException("La contraseña debe tener entre 8 y 20 caracteres", 400);
      }

      if (!STRONG_PASSWORD_PATTERN.matcher(newPassword).matches()) {
        throw new UserException(
            "La contraseña debe contener al menos una mayúscula, una minúscula, un número y un carácter especial (@$!%*#?&)",
            400);
      }

      String key = prefix + token;
      String userId = redis.opsForValue().get(key);

      if (userId == null) {
        log.warn("Intento de reseteo con token inválido o expirado");
        throw new UserException("El enlace de recuperación ha expirado o es inválido. Por favor solicita uno nuevo.",
            400);
      }

      kc.resetUserPassword(userId, newPassword);
      redis.delete(key);

      log.info("Contraseña reseteada exitosamente para usuario ID: {}", userId);
    } catch (UserException e) {
      throw e; // Re-lanzar excepciones ya manejadas
    } catch (Exception e) {
      log.error("Error al resetear contraseña: {}", e.getMessage(), e);
      throw new UserException("Error al resetear la contraseña", 500);
    }
  }
}
