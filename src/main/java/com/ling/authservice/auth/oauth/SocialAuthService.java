package com.ling.authservice.auth.oauth;

import com.ling.authservice.user.User;
import com.ling.authservice.user.UserService;
import com.ling.authservice.user.identity.IdentityService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.concurrent.ThreadLocalRandom;

@Service
@RequiredArgsConstructor
public class SocialAuthService {

    private final UserService userService;
    private final IdentityService identityService;

    private final OidcUserService delegate =
            new OidcUserService();

    public OidcUser loadUser(OidcUserRequest userRequest) {

        OidcUser oidcUser =
                delegate.loadUser(userRequest);

        String subject =
                oidcUser.getSubject();

        if (!StringUtils.hasText(subject)) {
            throw new IllegalStateException(
                    "OIDC provider did not return subject"
            );
        }

        String issuer =
                userRequest
                        .getClientRegistration()
                        .getProviderDetails()
                        .getIssuerUri();

        if (!StringUtils.hasText(issuer)) {
            throw new IllegalStateException(
                    "OIDC provider did not define issuer"
            );
        }

        /*
         * Пользователь уже привязан.
         */
        if (identityService.existsBy(
                subject,
                issuer
        )) {
            return oidcUser;
        }

        String email =
                oidcUser.getEmail();

        if (!StringUtils.hasText(email)) {
            throw new IllegalStateException(
                    "OIDC provider did not return email"
            );
        }

        User user;

        /*
         * Email уже существует:
         * подключаем social identity.
         */
        if (userService.existsByEmail(email)) {

            user = userService.findByEmail(email);

        } else {

            /*
             * Новый пользователь.
             */
            user = User.builder()
                    .email(email)
                    .username("user_" + generateId())
                    .build();

            user = userService.createHashed(user);
        }

        identityService.create(
                issuer,
                subject,
                user
        );

        return oidcUser;
    }

    private static String generateId() {

        long id =
                ThreadLocalRandom.current()
                        .nextLong(
                                100_000_000_000_000L,
                                1_000_000_000_000_000L
                        );

        return Long.toString(id);
    }
}