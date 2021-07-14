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
import com.nimbusds.jose.crypto.impl.AlgorithmSupportMessage;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.util.Base64URL;
import java.util.Map;
import java.util.Objects;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import lombok.AllArgsConstructor;
import lombok.NonNull;

@AllArgsConstructor
public class KmsSymmetricEncrypter extends KmsSymmetricCryptoProvider implements JWEEncrypter {

    @NonNull
    private final AWSKMS kms;

    @NonNull
    private final String keyId;

    private final Map<String, String> encryptionContext;

    public KmsSymmetricEncrypter(final AWSKMS kms, final String keyId) {
        this.kms = kms;
        this.keyId = keyId;
        this.encryptionContext = null;
    }

    @Override
    public JWECryptoParts encrypt(final JWEHeader header, final byte[] clearText)
            throws JOSEException {

        final JWEAlgorithm alg = header.getAlgorithm();
        final EncryptionMethod enc = header.getEncryptionMethod();

        if (!SUPPORTED_ALGORITHMS.contains(alg)) {
            throw new JOSEException(AlgorithmSupportMessage.unsupportedJWEAlgorithm(alg, SUPPORTED_ALGORITHMS));
        }

        if (!SUPPORTED_ENCRYPTION_METHODS.contains(enc)) {
            throw new JOSEException(
                    AlgorithmSupportMessage.unsupportedEncryptionMethod(enc, SUPPORTED_ENCRYPTION_METHODS));
        }

        final JWEHeader updatedHeader; // We need to work on the header
        final Base64URL encryptedKey; // The second JWE part

        // Generate and encrypt the CEK according to the enc method
        GenerateDataKeyResult generateDataKeyResult = generateDataKey(keyId, enc);
        final SecretKey cek = new SecretKeySpec(generateDataKeyResult.getPlaintext().array(), alg.toString());

        encryptedKey = Base64URL.encode(generateDataKeyResult.getCiphertextBlob().array());
        if (Objects.nonNull(encryptionContext)) {
            updatedHeader = new JWEHeader.Builder(header)
                    .customParams(Map.of(ENCRYPTION_CONTEXT_HEADER, encryptionContext))
                    .build();
        } else {
            updatedHeader = header; // simply copy ref
        }

        return ContentCryptoProvider.encrypt(updatedHeader, clearText, cek, encryptedKey, getJCAContext());
    }

    private GenerateDataKeyResult generateDataKey(String keyId, EncryptionMethod encryptionMethod)
            throws JOSEException {
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

    private GenerateDataKeyRequest buildGenerateDataKeyRequest(String keyId, EncryptionMethod encryptionMethod) {
        GenerateDataKeyRequest generateDataKeyRequest = new GenerateDataKeyRequest();
        generateDataKeyRequest.setKeyId(keyId);
        generateDataKeyRequest.setKeySpec(ENCRYPTION_METHOD_TO_DATA_KEY_SPEC_MAP.get(encryptionMethod));
        generateDataKeyRequest.setEncryptionContext(encryptionContext);
        return generateDataKeyRequest;
    }
}
