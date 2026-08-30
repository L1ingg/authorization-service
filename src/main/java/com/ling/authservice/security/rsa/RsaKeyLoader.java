package com.ling.authservice.security.rsa;

import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;
import org.springframework.util.StreamUtils;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Component
public class RsaKeyLoader {

    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    public RsaKeyLoader(ResourceLoader resourceLoader) {
        this.privateKey = loadPrivateKey(
                resourceLoader,
                "file:/etc/secrets/rsa/private.pem"
        );

        this.publicKey = loadPublicKey(
                resourceLoader,
                "file:/etc/secrets/rsa/public.pem"
        );
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    private PrivateKey loadPrivateKey(
            ResourceLoader resourceLoader,
            String location
    ) {
        try {
            Resource resource = resourceLoader.getResource(location);

            if (!resource.exists()) {
                throw new IllegalStateException(
                        "RSA private key not found: " + location
                );
            }

            String pem = StreamUtils.copyToString(
                    resource.getInputStream(),
                    StandardCharsets.UTF_8
            );

            String base64 = pem
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s+", "");

            byte[] keyBytes = Base64.getDecoder().decode(base64);

            PKCS8EncodedKeySpec spec =
                    new PKCS8EncodedKeySpec(keyBytes);

            return KeyFactory
                    .getInstance("RSA")
                    .generatePrivate(spec);

        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to load RSA private key",
                    e
            );
        }
    }

    private PublicKey loadPublicKey(
            ResourceLoader resourceLoader,
            String location
    ) {
        try {
            Resource resource = resourceLoader.getResource(location);

            if (!resource.exists()) {
                throw new IllegalStateException(
                        "RSA public key not found: " + location
                );
            }

            String pem = StreamUtils.copyToString(
                    resource.getInputStream(),
                    StandardCharsets.UTF_8
            );

            String base64 = pem
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s+", "");

            byte[] keyBytes = Base64.getDecoder().decode(base64);

            X509EncodedKeySpec spec =
                    new X509EncodedKeySpec(keyBytes);

            return KeyFactory
                    .getInstance("RSA")
                    .generatePublic(spec);

        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to load RSA public key",
                    e
            );
        }
    }
}