package com.ling.authservice.user.identity.common;

public class IdentityAlreadyExistsException extends RuntimeException {
    public IdentityAlreadyExistsException(String message) {
        super(message);
    }
}
