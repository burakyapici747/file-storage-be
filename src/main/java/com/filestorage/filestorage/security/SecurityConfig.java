package com.filestorage.filestorage.security;

import com.filestorage.filestorage.exception.CustomAuthenticationFailureHandler;
import com.filestorage.filestorage.filter.CustomAuthenticationFilter;
import com.filestorage.filestorage.service.JWTService;
import jakarta.validation.Validator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private final CustomAuthenticationProvider customAuthenticationProvider;
    private final JWTService jwtService;
    private final Validator validator;

    public SecurityConfig(CustomAuthenticationProvider customAuthenticationProvider, Validator validator,  JWTService jwtService) {
        this.customAuthenticationProvider = customAuthenticationProvider;
        this.validator = validator;
        this.jwtService = jwtService;
    }

    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration authenticationConfiguration
    ) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            AuthenticationConfiguration authenticationConfiguration,
            CustomAuthenticationFailureHandler customAuthenticationFailureHandler, Validator validator) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .cors(AbstractHttpConfigurer::disable)
                .addFilterBefore(new CustomAuthenticationFilter(authenticationManager(authenticationConfiguration), customAuthenticationFailureHandler, validator, jwtService), UsernamePasswordAuthenticationFilter.class)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .sessionManagement(session-> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(customAuthenticationProvider);

        return http.build();
    }
}
