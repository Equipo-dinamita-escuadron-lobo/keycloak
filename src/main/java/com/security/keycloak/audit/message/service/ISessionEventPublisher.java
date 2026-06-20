package com.security.keycloak.audit.message.service;

import com.security.keycloak.audit.message.dto.SessionEventDTO;

public interface ISessionEventPublisher {

    void publishLoginEvent(SessionEventDTO sessionEventDTO);

    void publishLogoutEvent(SessionEventDTO sessionEventDTO);

}