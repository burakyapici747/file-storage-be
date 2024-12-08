package com.filestorage.filestorage.exception;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.filestorage.filestorage.api.output.ErrorOutput;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.List;

@Component
public class CustomAuthenticationFailureHandler implements AuthenticationFailureHandler {
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void onAuthenticationFailure(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException exception
    ) throws IOException, ServletException {
        String errorMessage = "Authentication failed";
        int status = HttpStatus.UNAUTHORIZED.value();

        ErrorOutput errorOutput = new ErrorOutput(
                errorMessage,
                List.of("Authentication failed"),
                status,
                request.getRequestURI(),
                null
        );

        response.setStatus(status);
        response.setContentType("application/json");
        objectMapper.writeValue(response.getWriter(), errorOutput);
    }
}
