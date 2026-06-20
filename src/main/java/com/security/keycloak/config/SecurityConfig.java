package com.security.keycloak.config;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;

import com.security.keycloak.config.filters.JwtBlacklistFilter;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    @Autowired
    private JwtAuthConverter jwtAuthConverter;

    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity,
                                            JwtBlacklistFilter blacklistFilter) throws Exception {
         return httpSecurity
                 .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                 .csrf(csrf -> csrf.disable())
                 .authorizeHttpRequests(http -> http
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll() 
                        .requestMatchers(
                                "/api/keycloak/token/**", 
                                "/api/keycloak/register",
                                "/api/keycloak/forgot-password",
                                "/api/keycloak/reset-password",
                                "/swagger-ui/**",
                                "/v3/api-docs/**",
                                "/actuator/**"
                        ).permitAll()
                         .anyRequest()
                         .authenticated())
                 .oauth2ResourceServer(oauth -> oauth
                     .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                     .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthConverter))
                 )
                .addFilterBefore(blacklistFilter, BearerTokenAuthenticationFilter.class)
                .build();
     }
}