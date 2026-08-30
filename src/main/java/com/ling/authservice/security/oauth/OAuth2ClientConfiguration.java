package com.ling.authservice.security.oauth;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.UUID;

@Configuration
@RequiredArgsConstructor
@EnableConfigurationProperties(OAuthClientProperties.class)
public class OAuth2ClientConfiguration {

    private final PasswordEncoder passwordEncoder;
    private final OAuthClientProperties properties;

    @Bean
    RegisteredClientRepository registeredClientRepository(
            JdbcTemplate jdbcTemplate
    ) {
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }

    @Bean
    OAuth2AuthorizationService authorizationService(
            JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository
    ) {
        return new JdbcOAuth2AuthorizationService(
                jdbcTemplate,
                registeredClientRepository
        );
    }

    @Bean
    OAuth2AuthorizationConsentService authorizationConsentService(
            JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository
    ) {
        return new JdbcOAuth2AuthorizationConsentService(
                jdbcTemplate,
                registeredClientRepository
        );
    }

    @Bean
    ApplicationRunner registerOAuth2Client(
            RegisteredClientRepository registeredClientRepository
    ) {
        return _ -> {

            RegisteredClient existing =
                    registeredClientRepository.findByClientId(
                            properties.clientId()
                    );

            if (existing != null) {
                return;
            }

            if (properties.clientSecret() == null ||
                    properties.clientSecret().isBlank()) {
                throw new IllegalStateException(
                        "APP_OAUTH_CLIENT_SECRET is not configured"
                );
            }

            RegisteredClient client = RegisteredClient
                    .withId(UUID.randomUUID().toString())
                    .clientId(properties.clientId())
                    .clientSecret(
                            passwordEncoder.encode(properties.clientSecret())
                    )

                    .clientAuthenticationMethod(
                            ClientAuthenticationMethod.CLIENT_SECRET_BASIC
                    )

                    .authorizationGrantType(
                            AuthorizationGrantType.AUTHORIZATION_CODE
                    )

                    .authorizationGrantType(
                            AuthorizationGrantType.REFRESH_TOKEN
                    )

                    .redirectUri(properties.redirectUri())

                    .scope(OidcScopes.OPENID)
                    .scope(OidcScopes.PROFILE)
                    .scope(OidcScopes.EMAIL)

                    .clientSettings(
                            ClientSettings.builder()
                                    .requireProofKey(true)
                                    .requireAuthorizationConsent(true)
                                    .build()
                    )

                    .tokenSettings(
                            TokenSettings.builder()
                                    .accessTokenTimeToLive(
                                            Duration.ofMinutes(15)
                                    )
                                    .refreshTokenTimeToLive(
                                            Duration.ofDays(30)
                                    )
                                    .authorizationCodeTimeToLive(
                                            Duration.ofMinutes(2)
                                    )
                                    .reuseRefreshTokens(false)
                                    .build()
                    )

                    .build();

            registeredClientRepository.save(client);
        };
    }
}