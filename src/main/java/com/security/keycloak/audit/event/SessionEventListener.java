package com.security.keycloak.audit.event;

import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

import com.security.keycloak.audit.message.dto.SessionEventDTO;
import com.security.keycloak.audit.message.service.ISessionEventPublisher;
import com.security.keycloak.audit.message.util.SessionEventBuilder;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@RequiredArgsConstructor
@Slf4j
public class SessionEventListener {

    private final SessionEventBuilder sessionEventBuilder;
    private final ISessionEventPublisher sessionEventPublisher;

    @Async
    @EventListener
    public void handleUserLoggedIn(UserLoggedInEvent event) {
        try {
            SessionEventDTO sessionEvent = sessionEventBuilder.buildLoginEvent(
                    event.jwtToken(),
                    event.request());
            sessionEventPublisher.publishLoginEvent(sessionEvent);
        } catch (Exception e) {
            log.error("Failed to process UserLoggedInEvent", e);
        }
    }

    @Async
    @EventListener
    public void handleUserLoggedOut(UserLoggedOutEvent event) {
        try {
            SessionEventDTO sessionEvent = sessionEventBuilder.buildLogoutEvent(
                    event.jwtToken(),
                    event.request());

            sessionEventPublisher.publishLogoutEvent(sessionEvent);
        } catch (Exception e) {
            log.error("Error handling UserLoggedOutEvent", e);
        }
    }

}
