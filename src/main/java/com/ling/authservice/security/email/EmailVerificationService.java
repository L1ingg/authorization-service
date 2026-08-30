package com.ling.authservice.security.email;

import com.ling.authservice.auth.email.dto.EmailVerificationRequest;
import com.ling.authservice.security.email.dto.EmailRegisterMessage;
import com.ling.authservice.security.email.dto.EmailRegisterRequest;
import com.ling.authservice.security.email.dto.EmailRegisterResponse;
import com.ling.authservice.security.email.dto.EmailVerificationResponse;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import tools.jackson.databind.json.JsonMapper;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class EmailVerificationService {

    private static final Duration CODE_TTL = Duration.ofMinutes(15);
    private static final int CODE_LENGTH = 6;
    private static final int MAX_ATTEMPTS = 5;

    private static final String REDIS_KEY_PREFIX = "email-verification:";

    private static final SecureRandom RANDOM = new SecureRandom();

    private final JavaMailSender sender;
    private final RedisTemplate<String, String> redis;
    private final PasswordEncoder passwordEncoder;
    private final JsonMapper jsonMapper;

    public EmailRegisterResponse request(EmailRegisterRequest request) {
        String challengeId = UUID.randomUUID().toString();
        String code = generateCode();

        EmailRegisterMessage message = new EmailRegisterMessage(
                request.email(),
                request.username(),
                passwordEncoder.encode(request.password()),
                code
        );

        String key = REDIS_KEY_PREFIX + challengeId;

        redis.opsForValue().set(
                key,
                jsonMapper.writeValueAsString(message),
                CODE_TTL
        );

        sendVerificationEmail(request.email(), code);

        return new EmailRegisterResponse(challengeId);
    }

    public EmailVerificationResponse verify(EmailVerificationRequest request) {
        String key = REDIS_KEY_PREFIX + request.challengeId();

        String json = redis.opsForValue().get(key);

        if (json == null) {
            throw new EntityNotFoundException("Verification request not found or expired");
        }

        EmailRegisterMessage message =
                jsonMapper.readValue(json, EmailRegisterMessage.class);

        if (!message.code().equals(request.code())) {
            handleFailedAttempt(key, message);
            throw new IllegalArgumentException("Invalid verification code");
        }

        redis.delete(key);
        return EmailVerificationResponse.from(message);
    }

    private void handleFailedAttempt(
            String key,
            EmailRegisterMessage message
    ) {
        String attemptsKey = key + ":attempts";

        Long attempts = redis.opsForValue().increment(attemptsKey);

        if (attempts != null && attempts == 1) {
            redis.expire(attemptsKey, CODE_TTL);
        }

        if (attempts != null && attempts >= MAX_ATTEMPTS) {
            redis.delete(key);
            redis.delete(attemptsKey);
        }
    }

    private void sendVerificationEmail(String email, String code) {
        SimpleMailMessage message = new SimpleMailMessage();

        message.setTo(email);
        message.setSubject("Verify your email");
        message.setText("""
                Your verification code is: %s
                
                The code expires in 15 minutes.
                """.formatted(code));

        sender.send(message);
    }

    private String generateCode() {
        return String.format(
                "%0" + CODE_LENGTH + "d",
                RANDOM.nextInt(1_000_000)
        );
    }
}