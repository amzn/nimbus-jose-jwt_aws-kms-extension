package com.nimbusds.jose.aws.kms.crypto;

import com.amazonaws.services.kms.model.DataKeySpec;
import com.amazonaws.services.kms.model.EncryptionAlgorithmSpec;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.crypto.impl.PublicBaseJWEProvider;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

public abstract class KmsSymmetricCryptoProvider extends PublicBaseJWEProvider {

    /**
     * The supported JWE algorithms by the AWS crypto provider class.
     */
    public static final Set<JWEAlgorithm> SUPPORTED_ALGORITHMS;

    public static final Set<EncryptionMethod> SUPPORTED_ENCRYPTION_METHODS;

    public static final Map<EncryptionMethod, DataKeySpec> ENCRYPTION_METHOD_TO_DATA_KEY_SPEC_MAP;

    public static final String ENCRYPTION_CONTEXT_HEADER = "ec";

    static {
        Set<JWEAlgorithm> algs = new LinkedHashSet<>();
        algs.add(JWEAlgorithm.parse(EncryptionAlgorithmSpec.SYMMETRIC_DEFAULT.toString()));
        SUPPORTED_ALGORITHMS = Collections.unmodifiableSet(algs);

        Set<EncryptionMethod> methods = new LinkedHashSet<>();
        methods.add(EncryptionMethod.A128CBC_HS256);
        methods.add(EncryptionMethod.A256CBC_HS512);
        methods.add(EncryptionMethod.A128GCM);
        methods.add(EncryptionMethod.A256GCM);
        SUPPORTED_ENCRYPTION_METHODS = Collections.unmodifiableSet(methods);

        ENCRYPTION_METHOD_TO_DATA_KEY_SPEC_MAP = Map.ofEntries(
                Map.entry(EncryptionMethod.A256GCM, DataKeySpec.AES_256),
                Map.entry(EncryptionMethod.A256CBC_HS512, DataKeySpec.AES_256),
                Map.entry(EncryptionMethod.A128GCM, DataKeySpec.AES_128),
                Map.entry(EncryptionMethod.A128CBC_HS256, DataKeySpec.AES_128));
    }

    /**
     * Creates a new AES encryption / decryption provider.
     */
    protected KmsSymmetricCryptoProvider() {
        super(SUPPORTED_ALGORITHMS, ContentCryptoProvider.SUPPORTED_ENCRYPTION_METHODS);
    }
}
