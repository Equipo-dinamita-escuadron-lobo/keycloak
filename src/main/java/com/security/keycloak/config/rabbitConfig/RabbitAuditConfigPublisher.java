package com.security.keycloak.config.rabbitConfig;

import org.springframework.amqp.core.AmqpTemplate;
import org.springframework.amqp.core.TopicExchange;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.amqp.support.converter.Jackson2JsonMessageConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Configuration
@Profile("!test")
public class RabbitAuditConfigPublisher {

    public static final String AUDIT_EXCHANGE = "audit.exchange";
    public static final String OPERATION_EVENT_ROUTING_KEY = "operation.event";

    public static final String SESSION_EVENT_ROUTING_KEY = "session.event";

    @Bean
    public TopicExchange auditExchange() {
        return new TopicExchange(AUDIT_EXCHANGE, true, false);
    }

    @Bean
    public AmqpTemplate amqpTemplate(ConnectionFactory connectionFactory,
            Jackson2JsonMessageConverter jsonMessageConverter) {
        RabbitTemplate rabbitTemplate = new RabbitTemplate(connectionFactory);
        rabbitTemplate.setMessageConverter(jsonMessageConverter);
        return rabbitTemplate;
    }
}