package com.ling.authservice.security.oauth;


import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.oauth")
public record OAuthClientProperties(
        String clientId,
        String clientSecret,
        String redirectUri
) {
}
