package com.nimbusds.jose.aws.kms.crypto;

import com.amazonaws.services.kms.model.EncryptionAlgorithmSpec;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.crypto.impl.PublicBaseJWEProvider;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

public abstract class KmsSymmetricCryptoProvider extends PublicBaseJWEProvider {

    /**
     * The supported JWE algorithms by the AES crypto provider class.
     */
    public static final Set<JWEAlgorithm> SUPPORTED_ALGORITHMS;

    static {
        Set<JWEAlgorithm> algs = new LinkedHashSet<>();
        algs.add(JWEAlgorithm.parse(EncryptionAlgorithmSpec.SYMMETRIC_DEFAULT.toString()));
        SUPPORTED_ALGORITHMS = Collections.unmodifiableSet(algs);
    }


    /**
     * The Key Encryption Key (KEK).
     */
    private final String kek;


    /**
     * Creates a new AES encryption / decryption provider.
     *
     * @param kek The Key Encryption Key. Must be 128 bits (16 bytes), 192 bits (24 bytes) or 256 bits (32 bytes). Must
     *            not be {@code null}.
     * @throws KeyLengthException If the KEK length is invalid.
     */
    protected KmsSymmetricCryptoProvider(final String kek) {

        super(SUPPORTED_ALGORITHMS, ContentCryptoProvider.SUPPORTED_ENCRYPTION_METHODS);

        this.kek = kek;
    }

    /**
     * Gets the Key Encryption Key (KEK).
     *
     * @return The Key Encryption Key.
     */
    public String getKey() {
        return kek;
    }

}
