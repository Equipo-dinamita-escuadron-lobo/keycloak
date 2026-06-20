package com.security.keycloak.service.impl;

import com.security.keycloak.service.IMailService;
import lombok.RequiredArgsConstructor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MailServiceImpl implements IMailService {

  private final JavaMailSender sender;

  @Override
  public void send(String to, String subject, String body) {
    var msg = new SimpleMailMessage();
    msg.setTo(to);
    msg.setSubject(subject);
    msg.setText(body);
    sender.send(msg);
  }
}
