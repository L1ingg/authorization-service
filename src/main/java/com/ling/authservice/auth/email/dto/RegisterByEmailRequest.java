package com.ling.authservice.auth.email.dto;

public record RegisterByEmailRequest(
        String email,
        String username,
        String password
) {}
