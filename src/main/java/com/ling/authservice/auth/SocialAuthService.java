package com.ling.authservice.auth;

import com.ling.authservice.user.User;
import com.ling.authservice.user.UserService;
import com.ling.authservice.user.identity.IdentityService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

import java.util.concurrent.ThreadLocalRandom;

@Component
@RequiredArgsConstructor
public class SocialAuthService {

    private final UserService userService;
    private final IdentityService identityService;

    @Bean
    public OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService() {

        DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();

        return request -> {

            OAuth2User oauth2User = delegate.loadUser(request);

            String subject = oauth2User.getAttribute("sub");

            if (subject == null || subject.isBlank()) {
                throw new IllegalStateException(
                        "OIDC provider did not return subject"
                );
            }

            String issuer = request
                    .getClientRegistration()
                    .getProviderDetails()
                    .getIssuerUri();

            if (issuer == null || issuer.isBlank()) {
                throw new IllegalStateException(
                        "OIDC provider did not define issuer"
                );
            }

            if (identityService.existsBy(subject, issuer)) return oauth2User;

            String email = extractEmail(oauth2User);

            User user;
            if (userService.existsByEmail(email)) {
                user = userService.findByEmail(email);
            } else {
                user = User.builder()
                        .email(email)
                        .username("user_" + generateId())
                        .build();

                user = userService.create(user);
            }

            identityService.create(
                    issuer,
                    subject,
                    user
            );

            return oauth2User;
        };
    }

    private String extractEmail(OAuth2User oauth2User) {

        String email = oauth2User.getAttribute("email");

        if (email == null || email.isBlank()) {
            throw new IllegalStateException(
                    "OAuth2 provider did not return email"
            );
        }

        return email;
    }


    public static String generateId() {
        long id = ThreadLocalRandom.current()
                .nextLong(100_000_000_000_000L, 1_000_000_000_000_000L);

        return Long.toString(id);
    }
}