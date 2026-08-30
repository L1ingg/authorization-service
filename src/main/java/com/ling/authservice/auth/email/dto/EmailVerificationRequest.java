package com.ling.authservice.auth.email.dto;

public record EmailVerificationRequest(String challengeId, String code) {
}
