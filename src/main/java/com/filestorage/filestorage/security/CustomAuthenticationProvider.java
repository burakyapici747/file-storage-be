package com.filestorage.filestorage.security;

import com.filestorage.filestorage.service.CustomUserDetailsService;
import jakarta.persistence.EntityNotFoundException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {
    private final PasswordEncoder passwordEncoder;
    private final CustomUserDetailsService customUserDetailsService;

    public CustomAuthenticationProvider(PasswordEncoder passwordEncoder, CustomUserDetailsService customUserDetailsService) {
        this.passwordEncoder = passwordEncoder;
        this.customUserDetailsService = customUserDetailsService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        try{
            UserDetails userDetails = customUserDetailsService.loadUserByUsername(authentication.getName());
            return validatePassword(userDetails, (UsernamePasswordAuthenticationToken) authentication);
        }catch (Exception e){
            throw new RuntimeException("UserNotFoundException");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }

    private Authentication validatePassword(
            UserDetails userDetails,
            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken
    ) {
        if (passwordEncoder.matches(usernamePasswordAuthenticationToken.getCredentials().toString(), userDetails.getPassword())) {
            return new UsernamePasswordAuthenticationToken(userDetails, userDetails.getPassword(), userDetails.getAuthorities());
        }else{
            throw new EntityNotFoundException("UserNotFoundException");
        }
    }
}
