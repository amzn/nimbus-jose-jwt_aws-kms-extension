package com.nimbusds.jose.aws.kms.crypto;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.util.ByteUtils;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import javax.crypto.SecretKey;
import com.amazonaws.services.kms.model.EncryptionAlgorithmSpec;

public abstract class KmsSymmetricCryptoProvider extends BaseJWEProvider {

    /**
     * The supported JWE algorithms by the AES crypto provider class.
     */
    public static final Set<JWEAlgorithm> SUPPORTED_ALGORITHMS;


    /**
     * The supported encryption methods by the AES crypto provider class.
     */
    public static final Set<EncryptionMethod> SUPPORTED_ENCRYPTION_METHODS = ContentCryptoProvider.SUPPORTED_ENCRYPTION_METHODS;


    /**
     * The JWE algorithms compatible with each key size in bits.
     */
    public static final Map<Integer, Set<JWEAlgorithm>> COMPATIBLE_ALGORITHMS;


    static {
        Set<JWEAlgorithm> algs = new LinkedHashSet<>();
        algs.add(JWEAlgorithm.parse(EncryptionAlgorithmSpec.SYMMETRIC_DEFAULT.toString()));
        SUPPORTED_ALGORITHMS = Collections.unmodifiableSet(algs);

        Map<Integer,Set<JWEAlgorithm>> algsMap = new HashMap<>();
        Set<JWEAlgorithm> bit256Algs = new HashSet<>();

        bit256Algs.add(JWEAlgorithm.parse(EncryptionAlgorithmSpec.SYMMETRIC_DEFAULT.toString()));

        algsMap.put(256,Collections.unmodifiableSet(bit256Algs));
        COMPATIBLE_ALGORITHMS = Collections.unmodifiableMap(algsMap);
    }


    /**
     * The Key Encryption Key (KEK).
     */
    private final SecretKey kek;


    /**
     * Returns the compatible JWE algorithms for the specified Key
     * Encryption Key (CEK) length.
     *
     * @param kekLength The KEK length in bits.
     *
     * @return The compatible JWE algorithms.
     *
     * @throws KeyLengthException If the KEK length is not compatible.
     */
    private static Set<JWEAlgorithm> getCompatibleJWEAlgorithms(final int kekLength)
            throws KeyLengthException {

        Set<JWEAlgorithm> algs = COMPATIBLE_ALGORITHMS.get(kekLength);

        if (algs == null) {
            throw new KeyLengthException("The Key Encryption Key length must be 128 bits (16 bytes), 192 bits (24 bytes) or 256 bits (32 bytes)");
        }

        return algs;
    }


    /**
     * Creates a new AES encryption / decryption provider.
     *
     *  @param kek The Key Encryption Key. Must be 128 bits (16 bytes), 192
     *             bits (24 bytes) or 256 bits (32 bytes). Must not be
     *             {@code null}.
     *
     * @throws KeyLengthException If the KEK length is invalid.
     */
    protected KmsSymmetricCryptoProvider(final SecretKey kek)
            throws KeyLengthException {

        super(getCompatibleJWEAlgorithms(ByteUtils.bitLength(kek.getEncoded())), ContentCryptoProvider.SUPPORTED_ENCRYPTION_METHODS);

        this.kek = kek;
    }


    /**
     * Gets the Key Encryption Key (KEK).
     *
     * @return The Key Encryption Key.
     */
    public SecretKey getKey() {

        return kek;
    }

}
