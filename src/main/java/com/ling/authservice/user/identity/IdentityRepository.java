package com.ling.authservice.user.identity;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface IdentityRepository extends JpaRepository<Identity, UUID> {
    Optional<Identity> findBySubject(String subject);

    Optional<Identity> findBySubjectAndIssuer(String subject, String issuer);

    boolean existsBySubjectAndIssuer(String subject, String issuer);

}
