package com.nimbusds.jose.aws.kms.crypto.utils;

import com.google.common.collect.ImmutableMap;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.impl.AlgorithmSupportMessage;
import lombok.NonNull;
import lombok.experimental.UtilityClass;

import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Utility class containing JWE header related methods.
 */
@UtilityClass
public class JWEHeaderUtil {

    /**
     * Method to validation the algorithm and encryption-method of the passed JWE header.
     */
    public void validateJWEHeaderAlgorithms(
            @NonNull final JWEHeader header,
            @NonNull Set<JWEAlgorithm> supportedAlgorithms,
            @NonNull Set<EncryptionMethod> supportedEncryptionMethods) throws JOSEException {
        final JWEAlgorithm alg = header.getAlgorithm();
        final EncryptionMethod enc = header.getEncryptionMethod();

        if (!supportedAlgorithms.contains(alg)) {
            throw new JOSEException(AlgorithmSupportMessage.unsupportedJWEAlgorithm(alg, supportedAlgorithms));
        }

        if (!supportedEncryptionMethods.contains(enc)) {
            throw new JOSEException(
                    AlgorithmSupportMessage.unsupportedEncryptionMethod(enc, supportedEncryptionMethods));
        }
    }

    /**
     * Method to add encryption context to a {@link JWEHeader} object,
     * if the passed {@code encryptionContext} is non-null.
     * <p>
     * This method doesn't mutate the passed {@link JWEHeader} object. It rather returns a new {@link JWEHeader} object.
     */
    public JWEHeader getJWEHeaderWithEncryptionContext(
            @NonNull final JWEHeader header,
            @NonNull String encryptionContextHeaderName,
            Map<String, String> encryptionContext) {

        JWEHeader updatedHeader;
        if (Objects.nonNull(encryptionContext)) {
            updatedHeader = new JWEHeader.Builder(header)
                    .customParams(ImmutableMap.of(encryptionContextHeaderName, encryptionContext))
                    .build();
        } else {
            updatedHeader = header; // simply copy ref
        }

        return updatedHeader;
    }
}
