package com.ling.authservice.user.identity.common;

public class IdentityNotFoundException extends RuntimeException {
    public IdentityNotFoundException(String message) {
        super(message);
    }
}
