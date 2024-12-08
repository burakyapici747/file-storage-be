package com.filestorage.filestorage.api.output;

import java.util.List;

public record ErrorOutput(
        String message,
        List<String> errors,
        int status,
        String path,
        String timestamp
) {}
