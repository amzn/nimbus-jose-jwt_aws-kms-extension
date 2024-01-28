package com.nimbusds.jose.aws.kms.crypto.utils;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.impl.AlgorithmSupportMessage;
import java.util.Set;
import lombok.NonNull;
import lombok.experimental.UtilityClass;

/**
 * Utility class containing JWE header validation functions.
 */
@UtilityClass
public class JWEHeaderValidationUtil {

    /**
     * Function to validation the algorithm and encryption-method of the passed JWE header.
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
}
