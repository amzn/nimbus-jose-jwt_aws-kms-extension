package com.nimbusds.jose.aws.kms.crypto.impl;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.DataKeySpec;
import com.amazonaws.services.kms.model.EncryptionAlgorithmSpec;
import com.google.common.collect.ImmutableMap;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.crypto.impl.PublicBaseJWEProvider;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import lombok.Getter;
import lombok.NonNull;

public abstract class KmsSymmetricCryptoProvider extends PublicBaseJWEProvider {

    /**
     * The supported JWE algorithms by the AWS crypto provider class.
     */
    public static final Set<JWEAlgorithm> SUPPORTED_ALGORITHMS;

    public static final Set<EncryptionMethod> SUPPORTED_ENCRYPTION_METHODS;

    public static final Map<EncryptionMethod, DataKeySpec> ENCRYPTION_METHOD_TO_DATA_KEY_SPEC_MAP =
            ImmutableMap.<EncryptionMethod, DataKeySpec>builder()
                    .put(EncryptionMethod.A256GCM, DataKeySpec.AES_256)
                    .put(EncryptionMethod.A256CBC_HS512, DataKeySpec.AES_256)
                    .put(EncryptionMethod.A128GCM, DataKeySpec.AES_128)
                    .put(EncryptionMethod.A128CBC_HS256, DataKeySpec.AES_128)
                    .build();

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
    }

    @NonNull
    @Getter
    private final AWSKMS kms;

    @NonNull
    @Getter
    private final String keyId;

    @Getter
    private final Map<String, String> encryptionContext;

    protected KmsSymmetricCryptoProvider(@NonNull final AWSKMS kms, @NonNull final String keyId) {
        super(SUPPORTED_ALGORITHMS, ContentCryptoProvider.SUPPORTED_ENCRYPTION_METHODS);
        this.kms = kms;
        this.keyId = keyId;
        this.encryptionContext = null;
    }

    protected KmsSymmetricCryptoProvider(@NonNull final AWSKMS kms, @NonNull final String keyId,
            @NonNull final Map<String, String> encryptionContext) {
        super(SUPPORTED_ALGORITHMS, ContentCryptoProvider.SUPPORTED_ENCRYPTION_METHODS);
        this.kms = kms;
        this.keyId = keyId;
        this.encryptionContext = ImmutableMap.copyOf(encryptionContext);
    }
}
