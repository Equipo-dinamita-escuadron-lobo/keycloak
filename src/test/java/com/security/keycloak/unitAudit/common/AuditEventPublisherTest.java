package com.security.keycloak.unitAudit.common;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.amqp.core.AmqpTemplate;

import com.security.keycloak.audit.builder.OperationEventDto;
import com.security.keycloak.audit.publisher.AuditEventPublisher;
import com.security.keycloak.config.rabbitConfig.RabbitAuditConfigPublisher;

@ExtendWith(MockitoExtension.class)
class AuditEventPublisherTest {

    @Mock
    private AmqpTemplate amqpTemplate;

    private AuditEventPublisher publisher;

    @BeforeEach
    void setUp() {
        publisher = new AuditEventPublisher(amqpTemplate);
    }

    @Test
    @DisplayName("publish - debe enviar evento al exchange con routing key configurados")
    void publish_enviaEvento() {
        OperationEventDto dto = OperationEventDto.builder()
                .operationType("CREATE")
                .affectedTable("PROFILE")
                .build();

        publisher.publish(dto);

        verify(amqpTemplate).convertAndSend(
                RabbitAuditConfigPublisher.AUDIT_EXCHANGE,
                RabbitAuditConfigPublisher.OPERATION_EVENT_ROUTING_KEY,
                dto);
    }

    @Test
    @DisplayName("publish - si Rabbit falla no debe lanzar excepción")
    void publish_errorRabbitNoLanzaExcepcion() {
        OperationEventDto dto = OperationEventDto.builder()
                .operationType("CREATE")
                .affectedTable("PROFILE")
                .build();

        doThrow(new RuntimeException("Rabbit caído"))
                .when(amqpTemplate)
                .convertAndSend(
                        RabbitAuditConfigPublisher.AUDIT_EXCHANGE,
                        RabbitAuditConfigPublisher.OPERATION_EVENT_ROUTING_KEY,
                        dto);

        assertDoesNotThrow(() -> publisher.publish(dto));
    }
}
