package com.security.keycloak.audit.message.service;

import org.springframework.amqp.core.AmqpTemplate;
import org.springframework.stereotype.Service;

import com.security.keycloak.audit.message.dto.SessionEventDTO;
import com.security.keycloak.config.rabbitConfig.RabbitAuditConfigPublisher;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@RequiredArgsConstructor
public class SessionEventPublisherImpl implements ISessionEventPublisher {

    private final AmqpTemplate amqpTemplate;

    @Override
    public void publishLoginEvent(SessionEventDTO sessionEventDTO) {
        try {
            amqpTemplate.convertAndSend(
                    RabbitAuditConfigPublisher.AUDIT_EXCHANGE,
                    RabbitAuditConfigPublisher.SESSION_EVENT_ROUTING_KEY,
                    sessionEventDTO);
        } catch (Exception e) {
            log.error("Failed to publish login event: {}", e.getMessage());
        }
    }

    @Override
    public void publishLogoutEvent(SessionEventDTO sessionEventDTO) {
        try {
            amqpTemplate.convertAndSend(
                    RabbitAuditConfigPublisher.AUDIT_EXCHANGE,
                    RabbitAuditConfigPublisher.SESSION_EVENT_ROUTING_KEY,
                    sessionEventDTO);
        } catch (Exception e) {
            log.error("Error publishing logout event for user: {}", sessionEventDTO.getUserName(), e);
        }
    }

}
