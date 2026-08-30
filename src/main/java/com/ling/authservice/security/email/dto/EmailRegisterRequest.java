package com.ling.authservice.security.email.dto;

import com.ling.authservice.auth.email.dto.RegisterByEmailRequest;

public record EmailRegisterRequest(String email,
                                   String username,
                                   String password
) {
    public static EmailRegisterRequest from(RegisterByEmailRequest request) {
        return new EmailRegisterRequest(request.email(), request.username(), request.password());
    }
}
