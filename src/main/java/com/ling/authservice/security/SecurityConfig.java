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
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.DefaultRedirectStrategy;

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
     * =========================================================
     * AUTHORIZATION SERVER
     * =========================================================
     *
     * Обрабатывает:
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
     * =========================================================
     * BROWSER / BFF
     * =========================================================
     */
    @Bean
    @Order(2)
    SecurityFilterChain applicationSecurityFilterChain(
            HttpSecurity http,
            OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService,
            @Value("${app.login-page:/login}") String loginPage,
            AuthenticationSuccessHandler oauth2AuthenticationSuccessHandler
    ) throws Exception {

        http
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers(
                                "/api/auth/register",
                                "/api/auth/email/verify"
                        )
                )
                .authorizeHttpRequests(auth -> auth

                        /*
                         * OAuth2 / OIDC.
                         */
                        .requestMatchers(
                                "/oauth2/authorization/**",
                                "/login/oauth2/code/**"
                        ).permitAll()

                        /*
                         * Login / error.
                         */
                        .requestMatchers(
                                "/login",
                                "/error",
                                "/css/**",
                                "/js/**"
                        ).permitAll()

                        /*
                         * Публичные auth endpoints.
                         */
                        .requestMatchers(
                                "/api/auth/register",
                                "/api/auth/email/verify"
                        ).permitAll()

                        /*
                         * Browser API.
                         */
                        .requestMatchers("/api/**")
                        .authenticated()

                        /*
                         * Всё остальное защищено.
                         */
                        .anyRequest()
                        .authenticated()
                )

                /*
                 * Browser authentication = HttpSession.
                 */
                .sessionManagement(session ->
                        session.sessionCreationPolicy(
                                SessionCreationPolicy.IF_REQUIRED
                        )
                )

                /*
                 * Обычный email/password login.
                 *
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

                        /*
                         * После успешного OAuth login:
                         *
                         * Google/Microsoft
                         *       ↓
                         * /login/oauth2/code/{registrationId}
                         *       ↓
                         * SocialAuthService
                         *       ↓
                         * AuthenticationSuccessHandler
                         *       ↓
                         * http://localhost/oauth/callback
                         */
                        .successHandler(
                                oauth2AuthenticationSuccessHandler
                        )

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
     * =========================================================
     * OIDC USER SERVICE
     * =========================================================
     */
    @Bean
    OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService(
            SocialAuthService socialAuthService
    ) {
        return socialAuthService::loadUser;
    }


    /**
     * =========================================================
     * OAUTH2 SUCCESS HANDLER
     * =========================================================
     *
     * После успешной аутентификации возвращает browser
     * на frontend callback.
     */
    @Bean
    AuthenticationSuccessHandler oauth2AuthenticationSuccessHandler(
            @Value(
                    "${app.oauth.redirect-uri:http://localhost/oauth/callback}"
            )
            String redirectUri
    ) {

        RedirectStrategy redirectStrategy =
                new DefaultRedirectStrategy();

        return (request, response, authentication) -> {

            redirectStrategy.sendRedirect(
                    request,
                    response,
                    redirectUri
            );
        };
    }


    /**
     * =========================================================
     * PASSWORD ENCODER
     * =========================================================
     */
    @Bean
    PasswordEncoder passwordEncoder() {

        return PasswordEncoderFactories
                .createDelegatingPasswordEncoder();
    }


    /**
     * =========================================================
     * OIDC AUTHORITIES
     * =========================================================
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
     * =========================================================
     * RSA JWK SOURCE
     * =========================================================
     */
    @Bean
    JWKSource<SecurityContext> jwkSource() throws Exception {

        RSAPublicKey publicKey =
                (RSAPublicKey) rsaKeyLoader.getPublicKey();

        RSAPrivateKey privateKey =
                (RSAPrivateKey) rsaKeyLoader.getPrivateKey();

        RSAKey rsaKey =
                new RSAKey.Builder(publicKey)
                        .privateKey(privateKey)
                        .keyID("auth-key")
                        .build();

        return new ImmutableJWKSet<>(
                new JWKSet(rsaKey)
        );
    }


    /**
     * =========================================================
     * JWT DECODER
     * =========================================================
     */
    @Bean
    JwtDecoder jwtDecoder(
            JWKSource<SecurityContext> jwkSource
    ) {
        return OAuth2AuthorizationServerConfiguration
                .jwtDecoder(jwkSource);
    }


    /**
     * =========================================================
     * AUTHORIZATION SERVER ISSUER
     * =========================================================
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