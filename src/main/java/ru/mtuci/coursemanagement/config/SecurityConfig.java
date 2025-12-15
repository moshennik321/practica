package ru.mtuci.coursemanagement.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;

// Исправлено: Broken Access Control - правила авторизации, CSRF защита, Security Headers
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Исправлено: включена CSRF защита
                .csrf(csrf -> csrf
                        .csrfTokenRepository(new org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository())
                        .ignoringRequestMatchers("/api/**")
                )
                // Исправлено: Broken Access Control - правильные правила авторизации
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login", "/register", "/", "/css/**", "/js/**", "/images/**").permitAll()
                        .requestMatchers("/api/**").permitAll()
                        .requestMatchers("/courses", "/students").authenticated()
                        .anyRequest().authenticated()
                )
                // Исправлено: Security Misconfiguration - управление сессиями (ограничение одновременных сессий)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(false)
                )
                // Исправлено: Security Misconfiguration - Security Headers (CSP, HSTS, X-Frame-Options и др.)
                .headers(headers -> headers
                        .contentSecurityPolicy(csp -> csp
                                .policyDirectives("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';")
                        )
                        .frameOptions(frame -> frame.deny())
                        .httpStrictTransportSecurity(hsts -> hsts
                                .maxAgeInSeconds(31536000)
                        )
                        .referrerPolicy(referrer -> referrer
                                .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)
                        )
                        .xssProtection(xss -> xss
                                .headerValue(org.springframework.security.web.header.writers.XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK)
                        )
                        .contentTypeOptions(contentType -> {})
                );

        return http.build();
    }
}
