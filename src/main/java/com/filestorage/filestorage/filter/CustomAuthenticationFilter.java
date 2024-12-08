package com.filestorage.filestorage.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.filestorage.filestorage.api.input.LoginInput;
import com.filestorage.filestorage.api.output.ErrorOutput;
import com.filestorage.filestorage.api.output.SuccessOutput;
import com.filestorage.filestorage.exception.CustomAuthenticationFailureHandler;
import com.filestorage.filestorage.model.CustomUserDetails;
import com.filestorage.filestorage.service.JWTService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class CustomAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    private final AuthenticationManager authenticationManager;
    private final CustomAuthenticationFailureHandler customAuthenticationFailureHandler;
    private final Validator validator;
    private final JWTService jwtService;
    private static final AntPathRequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER =
            new AntPathRequestMatcher("/v1/api/login", "POST");

    public CustomAuthenticationFilter(
            AuthenticationManager authenticationManager,
            CustomAuthenticationFailureHandler customAuthenticationFailureHandler,
            Validator validator,
            JWTService jwtService
    ) {
        super(DEFAULT_ANT_PATH_REQUEST_MATCHER);
        this.authenticationManager = authenticationManager;
        this.customAuthenticationFailureHandler = customAuthenticationFailureHandler;
        setAuthenticationFailureHandler(customAuthenticationFailureHandler);
        this.jwtService = jwtService;
        this.validator = validator;
    }

    @Override
    public Authentication attemptAuthentication(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws AuthenticationException, IOException {
        LoginInput loginInput = obtainLoginInput(request);
        Set<ConstraintViolation<LoginInput>> violations = validator.validate(loginInput);
        if (!violations.isEmpty()) {
            handleValidationErrors(response, violations, request.getRequestURI());
            return null;
        }
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                new UsernamePasswordAuthenticationToken(loginInput.email(), loginInput.password());
        return authenticationManager.authenticate(usernamePasswordAuthenticationToken);
    }

    @Override
    protected void successfulAuthentication(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain,
            Authentication authResult
    ) throws IOException, ServletException{
        SecurityContextHolder.getContext().setAuthentication(authResult);
        UserDetails userDetails = (UserDetails) authResult.getPrincipal();
        String token = jwtService.generateToken(userDetails);
        
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), new HashMap<String, String>() {{
            put("token", token);
        }});
    }

    @Override
    protected void unsuccessfulAuthentication(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException failed
    ) throws IOException, ServletException{
        super.unsuccessfulAuthentication(request, response, failed);
        this.getFailureHandler().onAuthenticationFailure(request, response, failed);
    }

    private LoginInput obtainLoginInput(HttpServletRequest request) throws IOException {
        return new ObjectMapper().readValue(request.getInputStream(), LoginInput.class);
    }

    private void handleValidationErrors(
            HttpServletResponse response,
            Set<ConstraintViolation<LoginInput>> violations,
            String path
    ) throws IOException {
        response.setStatus(HttpStatus.BAD_REQUEST.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        List<String> errorMessages = violations.stream()
                .map(ConstraintViolation::getMessage)
                .toList();

        ErrorOutput errorResponse = new ErrorOutput(
                "\"Input validation error. Please check the provided data.",
                errorMessages,
                HttpStatus.BAD_REQUEST.value(),
                path,
                String.valueOf(System.currentTimeMillis())
        );

        ObjectMapper mapper = new ObjectMapper();
        String jsonResponse = mapper.writeValueAsString(errorResponse);

        response.getWriter().write(jsonResponse);
        response.getWriter().flush();
    }

    private void sendSuccessResponse(HttpServletResponse response, String accessToken) throws IOException {
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpStatus.OK.value());

        Map<String, String> data = new HashMap<>();
        data.put("accessToken", accessToken);

        SuccessOutput responseData = new SuccessOutput(
                "Login successful",
                data,
                HttpStatus.OK.value(),
                String.valueOf(System.currentTimeMillis())
        );

        new ObjectMapper().writeValue(response.getOutputStream(), responseData);
    }
}
