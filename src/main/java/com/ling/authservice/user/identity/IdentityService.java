package com.ling.authservice.user.identity;

import com.ling.authservice.user.User;
import com.ling.authservice.user.UserRepository;
import jakarta.persistence.EntityExistsException;
import jakarta.persistence.EntityNotFoundException;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class IdentityService {

    private final UserRepository userRepository;
    private final IdentityRepository identityRepository;

    public Identity save(Identity identity) {
        return identityRepository.save(identity);
    }

    @Transactional
    public Identity create(String issuer, String subject, User user) {
        if (identityRepository.existsBySubjectAndIssuer(subject, issuer)) throw new EntityExistsException(issuer + " is already connected");

        Identity identity = new Identity();
        identity.setIssuer(issuer);
        identity.setSubject(subject);
        identity.setUser(user);
        
        return save(identity);
    }

    public Identity create(Identity identity) {
        return create(identity.getIssuer(), identity.getSubject(), identity.getUser());
    }

    public Identity findBy(String subject, String issuer) {
        return identityRepository.findBySubjectAndIssuer(subject, issuer).orElseThrow(() -> new EntityNotFoundException("Identity not found: " + issuer));
    }

    public boolean existsBy(String subject, String issuer) {
        return identityRepository.existsBySubjectAndIssuer(subject, issuer);
    }

}
