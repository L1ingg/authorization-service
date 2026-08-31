package com.ling.authservice.security;

import com.ling.authservice.security.rsa.RsaKeyLoader;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedHashSet;
import java.util.Set;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final RsaKeyLoader rsaKeyLoader;

    /**
     * OAuth2 Authorization Server.
     *
     * Обрабатывает:
     * /oauth2/authorize
     * /oauth2/token
     * /oauth2/jwks
     * /.well-known/*
     *
     * Эта часть отвечает за выдачу OAuth2/OIDC токенов.
     */
    @Bean
    @Order(1)
    SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http,
            @Value("${app.login-page}") String loginPage
    ) throws Exception {

        http
                .oauth2AuthorizationServer(authorizationServer -> {
                    http.securityMatcher(
                            authorizationServer.getEndpointsMatcher()
                    );

                    authorizationServer.oidc(
                            Customizer.withDefaults()
                    );
                })

                .authorizeHttpRequests(auth -> auth
                        .anyRequest().authenticated()
                )

                .exceptionHandling(exceptions -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint(loginPage),
                                new MediaTypeRequestMatcher(
                                        MediaType.TEXT_HTML
                                )
                        )
                );

        return http.build();
    }

    /**
     * Bearer-only Resource Server.
     *
     * ВСЕ запросы /api/**:
     *
     * - stateless
     * - только Authorization: Bearer <JWT>
     * - CSRF отключён
     * - session authentication не используется
     */
    @Bean
    @Order(2)
    SecurityFilterChain apiSecurityFilterChain(
            HttpSecurity http
    ) throws Exception {

        http
                .securityMatcher("/api/**")

                .csrf(AbstractHttpConfigurer::disable)

                .sessionManagement(session ->
                        session.sessionCreationPolicy(
                                SessionCreationPolicy.STATELESS
                        )
                )

                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/api/auth/register",
                                "/api/auth/email/verify"
                        ).permitAll()

                        .anyRequest().authenticated()
                )

                .oauth2ResourceServer(oauth2 ->
                        oauth2.jwt(Customizer.withDefaults())
                );

        return http.build();
    }

    @Bean
    AuthorizationServerSettings authorizationServerSettings(
            @Value("${app.oauth.issuer}") String issuer
    ) {
        return AuthorizationServerSettings.builder()
                .issuer(issuer)
                .build();
    }

    /**
     * Password encoder.
     */
    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories
                .createDelegatingPasswordEncoder();
    }

    /**
     * Mapping authorities для OIDC login.
     */
    @Bean
    GrantedAuthoritiesMapper oauth2UserAuthoritiesMapper() {

        return authorities -> {

            Set<GrantedAuthority> mapped =
                    new LinkedHashSet<>(authorities);

            mapped.add(
                    FactorGrantedAuthority.fromAuthority(
                            FactorGrantedAuthority
                                    .AUTHORIZATION_CODE_AUTHORITY
                    )
            );

            return mapped;
        };
    }

    /**
     * RSA key pair для подписи JWT.
     */
    @Bean
    JWKSource<SecurityContext> jwkSource() throws Exception {

        RSAPublicKey publicKey =
                (RSAPublicKey) rsaKeyLoader.getPublicKey();

        RSAPrivateKey privateKey =
                (RSAPrivateKey) rsaKeyLoader.getPrivateKey();

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID("auth-key")
                .build();

        JWKSet jwkSet = new JWKSet(rsaKey);

        return new ImmutableJWKSet<>(jwkSet);
    }

    /**
     * JWT decoder для Authorization Server.
     */
    @Bean
    JwtDecoder jwtDecoder(
            JWKSource<SecurityContext> jwkSource
    ) {
        return OAuth2AuthorizationServerConfiguration
                .jwtDecoder(jwkSource);
    }


}