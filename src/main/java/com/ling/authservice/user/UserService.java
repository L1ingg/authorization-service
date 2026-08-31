package com.ling.authservice.user;

import com.ling.authservice.user.common.UserAlreadyExistsException;
import com.ling.authservice.user.common.UserNotFoundException;
import com.ling.authservice.user.identity.Identity;
import com.ling.authservice.user.identity.IdentityRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final IdentityRepository identityRepository;
    private final PasswordEncoder passwordEncoder;

    public User save(User user) {
        return userRepository.save(user);
    }

    @Transactional
    public User create(
            String username,
            String email,
            String password,
            Set<Identity> identities,
            Set<String> roles
    ) {

        if (userRepository.existsByUsername(username)) {
            throw new UserAlreadyExistsException(
                    "User with username: " + username + " already exists"
            );
        }

        if (userRepository.existsByEmail(email)) {
            throw new UserAlreadyExistsException(
                    "User with email: " + email + " already exists"
            );
        }

        if (identities != null) {
            for (Identity identity : identities) {
                if (identityRepository.existsBySubjectAndIssuer(
                        identity.getSubject(),
                        identity.getIssuer()
                )) {
                    throw new UserAlreadyExistsException(
                            "User already connected to: "
                                    + identity.getIssuer()
                    );
                }
            }
        }

        User user = User.builder()
                .username(username)
                .email(email)
                .password(password)
                .identities(
                        identities == null
                                ? Set.of()
                                : identities
                )
                .roles(
                        roles == null || roles.isEmpty()
                                ? Set.of("USER")
                                : roles
                )
                .build();

        return save(user);
    }

    public User create(User user) {
        return create(user.getUsername(), user.getEmail(), passwordEncoder.encode(user.getPassword()), user.getIdentities(), user.getRoles());
    }

    public User createHashed(User user) {
        return create(user.getUsername(), user.getEmail(), user.getPassword(), user.getIdentities(), user.getRoles());
    }

    public User findByEmail(String email) {
        return userRepository.findByEmail(email).orElseThrow(() -> new UserNotFoundException("User not found: " + email));
    }

    public boolean existsByEmail(String email) {
        return userRepository.existsByEmail(email);
    }

    public boolean existsByUsername(String username) {
        return userRepository.existsByUsername(username);
    }

    public User findByUsername(String username) {
        return userRepository.findByUsername(username).orElseThrow(() -> new UserNotFoundException("User not found: " + username));
    }
}
