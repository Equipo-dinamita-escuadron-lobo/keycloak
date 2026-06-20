package com.security.keycloak.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

public final class JwtUtils {
  private JwtUtils() {}

  public static String getJti(String token) {
    try {
      return Jwts.parser().build().parseClaimsJws(token).getBody().getId();
    } catch (io.jsonwebtoken.JwtException | IllegalArgumentException e) { return null; }
  }

  public static String getSub(String token) {
    try {
      return Jwts.parser().build().parseClaimsJws(token).getBody().getSubject();
    } catch (io.jsonwebtoken.JwtException | IllegalArgumentException e) { return null; }
  }

  public static long getTtlSeconds(String token) {
    try {
      Claims c = Jwts.parser().build().parseClaimsJws(token).getBody();
      long now = System.currentTimeMillis();
      long exp = (c.getExpiration() != null) ? c.getExpiration().getTime() : now;
      long ttlMs = Math.max(0, exp - now);
      return ttlMs / 1000L;
    } catch (io.jsonwebtoken.JwtException | IllegalArgumentException e) { return 0; }
  }
}