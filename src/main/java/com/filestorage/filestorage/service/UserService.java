package com.filestorage.filestorage.service;

import com.filestorage.filestorage.dto.UserDTO;
import com.filestorage.filestorage.model.User;
import com.filestorage.filestorage.repository.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserService {
    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public UserDTO getUserByEmail(String email){
        User user = findUserByEmail(email);
        return new UserDTO(user.getId(), user.getEmail(), user.getPassword(), user.getName(), user.getLastName());
    }

    private User findUserByEmail(String email) throws EntityNotFoundException {
        return userRepository.findByEmail((email))
                .orElseThrow(() -> new EntityNotFoundException("User not found"));
    }
}
