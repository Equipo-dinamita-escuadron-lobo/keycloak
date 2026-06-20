package com.security.keycloak.config.filters;

import com.security.keycloak.util.JwtUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtBlacklistFilter extends OncePerRequestFilter {

  private final StringRedisTemplate redis;

  @Value("${app.jwt.blacklist-prefix:jwt:black:}")
  private String prefix;

  @Override
  protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
      throws ServletException, IOException {
    String hdr = req.getHeader(HttpHeaders.AUTHORIZATION);
    if (hdr != null && hdr.startsWith("Bearer ")) {
      String token = hdr.substring(7);
      String jti = JwtUtils.getJti(token);
      if (jti != null && Boolean.TRUE.equals(redis.hasKey(prefix + jti))) {
        res.sendError(HttpStatus.UNAUTHORIZED.value(), "Token revocado");
        return;
      }
    }
    chain.doFilter(req, res);
  }
}