package com.ling.authservice.security.email.dto;

public record EmailVerificationResponse(String email,
                                       String username,
                                       String password
) {
    public static EmailVerificationResponse from(EmailRegisterMessage message) {
        return new EmailVerificationResponse(message.email(), message.username(), message.password());
    }
}
