package com.filestorage.filestorage.service;

import com.filestorage.filestorage.dto.UserDTO;
import com.filestorage.filestorage.model.CustomUserDetails;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    private final UserService userService;

    public CustomUserDetailsService(UserService userService) {
        this.userService = userService;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserDTO userDTO = userService.getUserByEmail(username);
        return new CustomUserDetails(
                userDTO.id(),
                userDTO.email(),
                userDTO.password(),
                null
        );
    }
}
