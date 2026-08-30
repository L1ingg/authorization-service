package com.ling.authservice.security.email.dto;

public record EmailRegisterMessage(String email,
                                   String username,
                                   String password,
                                   String code
) {
}
