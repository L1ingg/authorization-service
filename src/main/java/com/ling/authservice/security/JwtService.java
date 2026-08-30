package com.ling.authservice.security;

import com.ling.authservice.user.User;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Service
public class JwtService {

    private final SecretKey key;

    private final long accessExpiration;
    private final long refreshExpiration;

    public JwtService(
            @Value("${spring.security.jwt.secret}") String secret,
            @Value("${spring.security.jwt.access-expiration}") long accessExpiration,
            @Value("${spring.security.jwt.refresh-expiration}") long refreshExpiration
    ) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessExpiration = accessExpiration;
        this.refreshExpiration = refreshExpiration;
    }

    public String generateAccessToken(User user) {
        return generateToken(user, TokenType.ACCESS, accessExpiration);
    }

    public String generateRefreshToken(User user) {
        return generateToken(user, TokenType.REFRESH, refreshExpiration);
    }

    private String generateToken(User user, TokenType tokenType, long expiration) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + expiration);

        return Jwts.builder()
                .subject(user.getId().toString())
                .claim("email", user.getEmail())
                .claim("type", tokenType.name())
                .issuedAt(now)
                .expiration(expiry)
                .signWith(key)
                .compact();
    }

    public boolean isAccessToken(String token) {
        return TokenType.ACCESS.name().equals(getTokenType(token));
    }

    public boolean isRefreshToken(String token) {
        return TokenType.REFRESH.name().equals(getTokenType(token));
    }

    public String getUserId(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    private String getTokenType(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("type", String.class);
    }

    @Getter
    private enum TokenType {
        ACCESS,
        REFRESH
    }
}