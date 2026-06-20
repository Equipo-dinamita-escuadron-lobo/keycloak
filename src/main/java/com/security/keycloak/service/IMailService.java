package com.security.keycloak.service;

public interface IMailService {
  void send(String to, String subject, String body);
}
