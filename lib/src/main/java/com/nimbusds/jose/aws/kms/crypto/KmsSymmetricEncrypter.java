package com.nimbusds.jose.aws.kms.crypto;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.DependencyTimeoutException;
import com.amazonaws.services.kms.model.DisabledException;
import com.amazonaws.services.kms.model.GenerateDataKeyRequest;
import com.amazonaws.services.kms.model.GenerateDataKeyResult;
import com.amazonaws.services.kms.model.InvalidGrantTokenException;
import com.amazonaws.services.kms.model.InvalidKeyUsageException;
import com.amazonaws.services.kms.model.KMSInternalException;
import com.amazonaws.services.kms.model.KMSInvalidStateException;
import com.amazonaws.services.kms.model.KeyUnavailableException;
import com.amazonaws.services.kms.model.NotFoundException;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWECryptoParts;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.KeyException;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.impl.AlgorithmSupportMessage;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.util.Base64URL;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import lombok.NonNull;

public class KmsSymmetricEncrypter extends KmsSymmetricCryptoProvider implements JWEEncrypter {

    @NonNull
    private final AWSKMS kms;

    @NonNull
    private final String keyId;


    /**
     * Creates a new AES encrypter.
     *
     * @param keyId The Key Encryption Key. Must be 128 bits (16 bytes), 192 bits (24 bytes) or 256 bits (32 bytes).
     *              Must not be {@code null}.
     * @param kms
     * @throws KeyLengthException If the KEK length is invalid.
     */
    public KmsSymmetricEncrypter(final String keyId, final AWSKMS kms)
            throws KeyLengthException {
        this.kms = kms;
        this.keyId = keyId;
    }

    @Override
    public JWECryptoParts encrypt(final JWEHeader header, final byte[] clearText)
            throws JOSEException {

        final JWEAlgorithm alg = header.getAlgorithm();

        if (!SUPPORTED_ALGORITHMS.contains(alg)) {
            throw new JOSEException(AlgorithmSupportMessage.unsupportedJWEAlgorithm(alg, SUPPORTED_ALGORITHMS));
        }

        final JWEHeader updatedHeader; // We need to work on the header
        final Base64URL encryptedKey; // The second JWE part

        // Generate and encrypt the CEK according to the enc method
        final EncryptionMethod enc = header.getEncryptionMethod();
        // data gene
        GenerateDataKeyResult generateDataKeyResult = generateDataKey(keyId, header.getAlgorithm().toString());
        final SecretKey cek = new SecretKeySpec(generateDataKeyResult.getPlaintext().array(), "AES");

        encryptedKey = Base64URL.encode(generateDataKeyResult.getCiphertextBlob().array());
        updatedHeader = header; // simply copy ref

        return ContentCryptoProvider.encrypt(updatedHeader, clearText, cek, encryptedKey, getJCAContext());
    }

    private GenerateDataKeyResult generateDataKey(String keyId, String encryptionMethod) throws JOSEException {
        try {
            return kms.generateDataKey(buildGenerateDataKeyRequest(keyId, encryptionMethod));
        } catch (NotFoundException | DisabledException | InvalidKeyUsageException | KeyUnavailableException
                | KMSInvalidStateException e) {
            throw new KeyException("An error occurred while using Key");
        } catch (DependencyTimeoutException | InvalidGrantTokenException
                | KMSInternalException e) {
            throw new JOSEException("A temporary error was thrown from KMS.");
        }
    }

    private GenerateDataKeyRequest buildGenerateDataKeyRequest(String keyId, String encryptionMethod) {
        GenerateDataKeyRequest generateDataKeyRequest = new GenerateDataKeyRequest();
        generateDataKeyRequest.setKeyId(keyId);
        generateDataKeyRequest.setKeySpec(encryptionMethod);
        return generateDataKeyRequest;
    }
}
