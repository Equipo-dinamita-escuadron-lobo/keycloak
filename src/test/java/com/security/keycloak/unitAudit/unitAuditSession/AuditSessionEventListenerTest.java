package com.security.keycloak.unitAudit.unitAuditSession;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.*;

import jakarta.servlet.http.HttpServletRequest;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.security.keycloak.audit.event.SessionEventListener;
import com.security.keycloak.audit.event.UserLoggedInEvent;
import com.security.keycloak.audit.event.UserLoggedOutEvent;
import com.security.keycloak.audit.message.dto.SessionEventDTO;
import com.security.keycloak.audit.message.service.ISessionEventPublisher;
import com.security.keycloak.audit.message.util.SessionEventBuilder;

import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(MockitoExtension.class)
class AuditSessionEventListenerTest {

    @Mock
    private SessionEventBuilder sessionEventBuilder;

    @Mock
    private ISessionEventPublisher sessionEventPublisher;

    @Mock
    private HttpServletRequest request;

    private SessionEventListener listener;

    @BeforeEach
    void setUp() {
        listener = new SessionEventListener(sessionEventBuilder, sessionEventPublisher);
    }

    @Test
    @DisplayName("handleUserLoggedIn - construye y publica evento de login")
    void handleUserLoggedIn_publicaEvento() {
        UserLoggedInEvent event = new UserLoggedInEvent("jwt-login", request);
        SessionEventDTO dto = sessionEventDto("LOGIN");

        when(sessionEventBuilder.buildLoginEvent("jwt-login", request)).thenReturn(dto);

        listener.handleUserLoggedIn(event);

        verify(sessionEventBuilder).buildLoginEvent("jwt-login", request);
        verify(sessionEventPublisher).publishLoginEvent(dto);
    }

    @Test
    @DisplayName("handleUserLoggedIn - si falla no lanza excepción")
    void handleUserLoggedIn_errorNoLanzaExcepcion() {
        UserLoggedInEvent event = new UserLoggedInEvent("jwt-login", request);

        when(sessionEventBuilder.buildLoginEvent("jwt-login", request))
                .thenThrow(new RuntimeException("error"));

        assertDoesNotThrow(() -> listener.handleUserLoggedIn(event));

        verify(sessionEventPublisher, never()).publishLoginEvent(any());
    }

    @Test
    @DisplayName("handleUserLoggedOut - construye y publica evento de logout")
    void handleUserLoggedOut_publicaEvento() {
        UserLoggedOutEvent event = new UserLoggedOutEvent("jwt-logout", request);
        SessionEventDTO dto = sessionEventDto("LOGOUT");

        when(sessionEventBuilder.buildLogoutEvent("jwt-logout", request)).thenReturn(dto);

        listener.handleUserLoggedOut(event);

        verify(sessionEventBuilder).buildLogoutEvent("jwt-logout", request);
        verify(sessionEventPublisher).publishLogoutEvent(dto);
    }

    @Test
    @DisplayName("handleUserLoggedOut - si falla no lanza excepción")
    void handleUserLoggedOut_errorNoLanzaExcepcion() {
        UserLoggedOutEvent event = new UserLoggedOutEvent("jwt-logout", request);

        when(sessionEventBuilder.buildLogoutEvent("jwt-logout", request))
                .thenThrow(new RuntimeException("error"));

        assertDoesNotThrow(() -> listener.handleUserLoggedOut(event));

        verify(sessionEventPublisher, never()).publishLogoutEvent(any());
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
