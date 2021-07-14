package com.nimbusds.jose.aws.kms.crypto;

import com.amazonaws.services.kms.model.EncryptionAlgorithmSpec;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.crypto.impl.PublicBaseJWEProvider;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

public abstract class KmsSymmetricCryptoProvider extends PublicBaseJWEProvider {

    /**
     * The supported JWE algorithms by the AWS crypto provider class.
     */
    public static final Set<JWEAlgorithm> SUPPORTED_ALGORITHMS;

    static {
        Set<JWEAlgorithm> algs = new LinkedHashSet<>();
        algs.add(JWEAlgorithm.parse(EncryptionAlgorithmSpec.SYMMETRIC_DEFAULT.toString()));
        SUPPORTED_ALGORITHMS = Collections.unmodifiableSet(algs);
    }

    /**
     * Creates a new AES encryption / decryption provider.
     */
    protected KmsSymmetricCryptoProvider() {
        super(SUPPORTED_ALGORITHMS, ContentCryptoProvider.SUPPORTED_ENCRYPTION_METHODS);
    }
}
