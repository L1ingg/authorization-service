package com.ling.authservice.security.oauth;

public class InvalidOAuth2UserException extends RuntimeException {
    public InvalidOAuth2UserException(String message) {
        super(message);
    }
}
