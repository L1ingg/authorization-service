CREATE TABLE users (
                       id UUID PRIMARY KEY,
                       username VARCHAR(32) NOT NULL UNIQUE,
                       email VARCHAR(255) UNIQUE,
                       password VARCHAR(255)
);

CREATE TABLE identities (
                            id UUID PRIMARY KEY,
                            issuer VARCHAR(512) NOT NULL,
                            subject VARCHAR(255) NOT NULL,
                            user_id UUID NOT NULL,

                            CONSTRAINT fk_identity_user
                                FOREIGN KEY (user_id)
                                    REFERENCES users (id)
                                    ON DELETE CASCADE,

                            CONSTRAINT uk_identity_issuer_subject
                                UNIQUE (issuer, subject)
);

CREATE TABLE user_roles (
                            user_id UUID NOT NULL,
                            role VARCHAR(255) NOT NULL,

                            CONSTRAINT fk_user_roles_user
                                FOREIGN KEY (user_id)
                                    REFERENCES users (id)
                                    ON DELETE CASCADE,

                            CONSTRAINT uk_user_role
                                UNIQUE (user_id, role)
);

CREATE INDEX idx_identity_user_id
    ON identities (user_id);