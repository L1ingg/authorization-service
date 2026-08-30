package com.ling.authservice.user.identity;

import com.ling.authservice.user.User;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.UUID;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Table(
        name = "identities",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_identity_issuer_subject",
                        columnNames = {"issuer", "subject"}
                )
        }
)
public class Identity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, updatable = false, length = 512)
    private String issuer;

    @Column(nullable = false, updatable = false)
    private String subject;

    @ManyToOne(optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;
}
