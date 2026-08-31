package com.ling.authservice.security;

import com.ling.authservice.auth.oauth.SocialAuthService;
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
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
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
     * Authorization Server.
     *
     * Обрабатывает OAuth2/OIDC endpoints:
     *
     * /oauth2/authorize
     * /oauth2/token
     * /oauth2/jwks
     * /.well-known/*
     */
    @Bean
    @Order(1)
    SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http
    ) throws Exception {

        http
                .oauth2AuthorizationServer(authorizationServer -> {

                    http.securityMatcher(
                            authorizationServer.getEndpointsMatcher()
                    );

                    authorizationServer
                            .oidc(Customizer.withDefaults());
                })

                .authorizeHttpRequests(auth -> auth
                        .anyRequest().authenticated()
                )

                .exceptionHandling(exceptions -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint(
                                        "/login"
                                ),
                                new MediaTypeRequestMatcher(
                                        MediaType.TEXT_HTML
                                )
                        )
                );

        return http.build();
    }

    /**
     * Browser / BFF.
     *
     * Здесь browser работает через HttpSession.
     *
     * Google/Microsoft login:
     *
     * /oauth2/authorization/google
     * /oauth2/authorization/microsoft
     *
     * Local login:
     *
     * POST /login
     *
     * Browser получает JSESSIONID.
     */
    @Bean
    @Order(2)
    SecurityFilterChain applicationSecurityFilterChain(
            HttpSecurity http,
            OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService,
            @Value("${app.login-page:/login}") String loginPage
    ) throws Exception {

        http
                .authorizeHttpRequests(auth -> auth

                        /*
                         * Публичные endpoints.
                         */
                        .requestMatchers(
                                "/login",
                                "/oauth2/authorization/**",
                                "/login/oauth2/code/**",
                                "/error",
                                "/css/**",
                                "/js/**",
                                "/api/auth/register",
                                "/api/auth/email/verify"
                        ).permitAll()

                        /*
                         * Browser API.
                         *
                         * Здесь authentication берётся
                         * из HttpSession.
                         */
                        .requestMatchers("/api/**")
                        .authenticated()

                        /*
                         * Всё остальное тоже требует login.
                         */
                        .anyRequest()
                        .authenticated()
                )

                /*
                 * Browser authentication = session.
                 */
                .sessionManagement(session ->
                        session.sessionCreationPolicy(
                                SessionCreationPolicy.IF_REQUIRED
                        )
                )

                /*
                 * Обычный login по email/password.
                 *
                 * GET  /login
                 * POST /login
                 */
                .formLogin(form -> form
                        .loginPage(loginPage)
                        .loginProcessingUrl("/login")
                        .permitAll()
                )

                /*
                 * Google / Microsoft.
                 */
                .oauth2Login(oauth2 -> oauth2
                        .loginPage(loginPage)
                        .userInfoEndpoint(userInfo -> userInfo
                                .oidcUserService(oidcUserService)
                        )
                )

                /*
                 * Backend является OAuth2 Client.
                 */
                .oauth2Client(Customizer.withDefaults());

        return http.build();
    }

    /**
     * Наш OIDC user service.
     */
    @Bean
    OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService(
            SocialAuthService socialAuthService
    ) {
        return socialAuthService::loadUser;
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
     * Authorities для OIDC users.
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

        return new ImmutableJWKSet<>(
                new JWKSet(rsaKey)
        );
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

    /**
     * OAuth issuer.
     */
    @Bean
    AuthorizationServerSettings authorizationServerSettings(
            @Value("${app.oauth.issuer}") String issuer
    ) {
        return AuthorizationServerSettings.builder()
                .issuer(issuer)
                .build();
    }
}