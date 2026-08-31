package com.ling.authservice.auth.email;

import com.ling.authservice.auth.email.dto.EmailVerificationRequest;
import com.ling.authservice.auth.email.dto.RegisterByEmailRequest;
import com.ling.authservice.security.email.EmailVerificationService;
import com.ling.authservice.security.email.dto.EmailRegisterRequest;
import com.ling.authservice.security.email.dto.EmailRegisterResponse;
import com.ling.authservice.security.email.dto.EmailVerificationResponse;
import com.ling.authservice.user.User;
import com.ling.authservice.user.UserService;
import com.ling.authservice.user.common.UserAlreadyExistsException;
import jakarta.persistence.EntityExistsException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EmailAuthService {
    private final EmailVerificationService emailVerificationService;
    private final UserService userService;

    public EmailRegisterResponse register(RegisterByEmailRequest request) {
        if (userService.existsByEmail(request.email())) throw new UserAlreadyExistsException("User with email already exists: " + request.email());
        if (userService.existsByUsername(request.username())) throw new UserAlreadyExistsException("User with username already exists: " + request.username());
        return emailVerificationService.request(EmailRegisterRequest.from(request));
    }

    public void verifyEmail(EmailVerificationRequest request) {
        EmailVerificationResponse response = emailVerificationService.verify(request);
        User user = User.builder()
                .email(response.email())
                .username(response.username())
                .password(response.password())
                .build();
        userService.createHashed(user);
    }
}
