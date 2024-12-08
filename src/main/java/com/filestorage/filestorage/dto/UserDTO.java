package com.filestorage.filestorage.dto;

public record UserDTO (
        String id,
        String email,
        String password,
        String name,
        String lastName
) {}
