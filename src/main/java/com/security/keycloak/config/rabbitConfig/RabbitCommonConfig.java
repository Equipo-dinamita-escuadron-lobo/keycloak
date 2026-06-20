package com.security.keycloak.config.rabbitConfig;

import org.springframework.amqp.support.converter.Jackson2JsonMessageConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import lombok.extern.slf4j.Slf4j;

import org.springframework.amqp.rabbit.config.SimpleRabbitListenerContainerFactory;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.rabbit.listener.RabbitListenerContainerFactory;
import org.springframework.amqp.rabbit.listener.SimpleMessageListenerContainer;
import org.springframework.boot.autoconfigure.amqp.SimpleRabbitListenerContainerFactoryConfigurer;

/**
 * @brief Configuración común de RabbitMQ para mensajería
 *
 *        Define configuración compartida para mensajería RabbitMQ: conversor
 *        JSON
 *        y factory de listeners para procesamiento automático de mensajes.
 */
@Configuration
@Slf4j
@Profile("!test")
public class RabbitCommonConfig {
    /**
     * @brief Configura conversor JSON para mensajes RabbitMQ
     * @return Conversor JSON configurado para mensajes RabbitMQ
     */
    @Bean
    Jackson2JsonMessageConverter jsonMessageConverter() {
        return new Jackson2JsonMessageConverter();
    }

    /**
     * @brief Crea factory personalizada de listeners con conversión JSON
     * @param connectionFactory Factory de conexión a RabbitMQ
     * @param configurer        Configurador automático para factory de listeners
     * @return Factory de listeners configurada con conversor JSON
     */
    @Bean
    RabbitListenerContainerFactory<SimpleMessageListenerContainer> rabbitListenerContainerFactory(
            ConnectionFactory connectionFactory,
            SimpleRabbitListenerContainerFactoryConfigurer configurer) {
        SimpleRabbitListenerContainerFactory factory = new SimpleRabbitListenerContainerFactory();
        configurer.configure(factory, connectionFactory);
        factory.setMessageConverter(jsonMessageConverter());
        return factory;
    }
}
