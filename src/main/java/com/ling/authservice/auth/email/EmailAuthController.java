package com.ling.authservice.auth.email;

import com.ling.authservice.auth.email.dto.EmailVerificationRequest;
import com.ling.authservice.auth.email.dto.RegisterByEmailRequest;
import com.ling.authservice.security.email.dto.EmailRegisterResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class EmailAuthController {

    private final EmailAuthService emailAuthService;

    @PostMapping("/register")
    public ResponseEntity<EmailRegisterResponse> register(
            @RequestBody RegisterByEmailRequest request
    ) {
        return ResponseEntity.ok(
                emailAuthService.register(request)
        );
    }

    @PostMapping("/email/verify")
    public ResponseEntity<Void> verifyEmail(
            @RequestBody EmailVerificationRequest request
    ) {

        emailAuthService.verifyEmail(request);

        return ResponseEntity.ok().build();
    }
}