package com.security.keycloak.unitAudit.unitAuditSession;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.*;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.amqp.core.AmqpTemplate;

import com.security.keycloak.audit.message.dto.SessionEventDTO;
import com.security.keycloak.audit.message.service.SessionEventPublisherImpl;
import com.security.keycloak.config.rabbitConfig.RabbitAuditConfigPublisher;

@ExtendWith(MockitoExtension.class)
class AuditSessionEventPublisherImplTest {

    @Mock
    private AmqpTemplate amqpTemplate;

    private SessionEventPublisherImpl publisher;

    @BeforeEach
    void setUp() {
        publisher = new SessionEventPublisherImpl(amqpTemplate);
    }

    @Test
    @DisplayName("publishLoginEvent - debe publicar evento de login")
    void publishLoginEvent_publicaEvento() {
        SessionEventDTO dto = sessionEventDto("LOGIN");

        publisher.publishLoginEvent(dto);

        verify(amqpTemplate).convertAndSend(
                RabbitAuditConfigPublisher.AUDIT_EXCHANGE,
                RabbitAuditConfigPublisher.SESSION_EVENT_ROUTING_KEY,
                dto);
    }

    @Test
    @DisplayName("publishLoginEvent - si Rabbit falla no lanza excepción")
    void publishLoginEvent_errorRabbitNoLanzaExcepcion() {
        SessionEventDTO dto = sessionEventDto("LOGIN");

        doThrow(new RuntimeException("Rabbit caído"))
                .when(amqpTemplate)
                .convertAndSend(
                        RabbitAuditConfigPublisher.AUDIT_EXCHANGE,
                        RabbitAuditConfigPublisher.SESSION_EVENT_ROUTING_KEY,
                        dto);

        assertDoesNotThrow(() -> publisher.publishLoginEvent(dto));
    }

    @Test
    @DisplayName("publishLogoutEvent - debe publicar evento de logout")
    void publishLogoutEvent_publicaEvento() {
        SessionEventDTO dto = sessionEventDto("LOGOUT");

        publisher.publishLogoutEvent(dto);

        verify(amqpTemplate).convertAndSend(
                RabbitAuditConfigPublisher.AUDIT_EXCHANGE,
                RabbitAuditConfigPublisher.SESSION_EVENT_ROUTING_KEY,
                dto);
    }

    @Test
    @DisplayName("publishLogoutEvent - si Rabbit falla no lanza excepción")
    void publishLogoutEvent_errorRabbitNoLanzaExcepcion() {
        SessionEventDTO dto = sessionEventDto("LOGOUT");

        doThrow(new RuntimeException("Rabbit caído"))
                .when(amqpTemplate)
                .convertAndSend(
                        RabbitAuditConfigPublisher.AUDIT_EXCHANGE,
                        RabbitAuditConfigPublisher.SESSION_EVENT_ROUTING_KEY,
                        dto);

        assertDoesNotThrow(() -> publisher.publishLogoutEvent(dto));
    }

    private SessionEventDTO sessionEventDto(String action) {
        return SessionEventDTO.builder()
                .sessionId("SESSION-1")
                .userId("USER-1")
                .userName("maria")
                .userRole(List.of("Administrador"))
                .action(action)
                .actionAt(Instant.now())
                .ipAddress("127.0.0.1")
                .build();
    }
}
