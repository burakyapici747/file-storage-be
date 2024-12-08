package com.filestorage.filestorage.api.output;

public record SuccessOutput (
        String message,
        Object data,
        int status,
        String timestamp
){}
