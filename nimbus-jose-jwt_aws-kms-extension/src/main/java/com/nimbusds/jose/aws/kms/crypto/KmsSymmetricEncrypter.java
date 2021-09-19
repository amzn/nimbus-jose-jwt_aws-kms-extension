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
import com.google.common.collect.ImmutableMap;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWECryptoParts;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.RemoteKeySourceException;
import com.nimbusds.jose.aws.kms.crypto.impl.KmsAsymmetricRSASSAProvider;
import com.nimbusds.jose.aws.kms.crypto.impl.KmsSymmetricCryptoProvider;
import com.nimbusds.jose.aws.kms.exceptions.TemporaryJOSEException;
import com.nimbusds.jose.crypto.impl.AlgorithmSupportMessage;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.util.Base64URL;
import java.util.Map;
import java.util.Objects;
import javax.annotation.concurrent.ThreadSafe;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import lombok.NonNull;

/**
 * Encrypter implementation for SYMMETRIC (AES based) signing with public/private key stored in AWS KMS.
 * <p>
 * See {@link KmsSymmetricCryptoProvider} for supported algorithms and encryption methods, and for details of various
 * constructor parameters.
 */
@ThreadSafe
public class KmsSymmetricEncrypter extends KmsSymmetricCryptoProvider implements JWEEncrypter {

    public KmsSymmetricEncrypter(@NonNull final AWSKMS kms, @NonNull final String keyId) {
        super(kms, keyId);
    }

    public KmsSymmetricEncrypter(@NonNull final AWSKMS kms, @NonNull final String keyId,
            @NonNull final Map<String, String> encryptionContext) {
        super(kms, keyId, encryptionContext);
    }

    @Override
    public JWECryptoParts encrypt(@NonNull final JWEHeader header, @NonNull final byte[] clearText)
            throws JOSEException {

        validateJWEHeader(header);

        final JWEHeader updatedHeader; // We need to work on the header
        final Base64URL encryptedKey; // The second JWE part

        // Generate and encrypt the CEK according to the enc method
        GenerateDataKeyResult generateDataKeyResult = generateDataKey(getKeyId(), header.getEncryptionMethod());
        final SecretKey cek = new SecretKeySpec(
                generateDataKeyResult.getPlaintext().array(), header.getAlgorithm().toString());

        encryptedKey = Base64URL.encode(generateDataKeyResult.getCiphertextBlob().array());
        if (Objects.nonNull(getEncryptionContext())) {
            updatedHeader = new JWEHeader.Builder(header)
                    .customParams(ImmutableMap.of(ENCRYPTION_CONTEXT_HEADER, getEncryptionContext()))
                    .build();
        } else {
            updatedHeader = header; // simply copy ref
        }

        return ContentCryptoProvider.encrypt(updatedHeader, clearText, cek, encryptedKey, getJCAContext());
    }

    private GenerateDataKeyResult generateDataKey(String keyId, EncryptionMethod encryptionMethod)
            throws JOSEException {
        try {
            return getKms().generateDataKey(new GenerateDataKeyRequest()
                    .withKeyId(keyId)
                    .withKeySpec(ENCRYPTION_METHOD_TO_DATA_KEY_SPEC_MAP.get(encryptionMethod))
                    .withEncryptionContext(getEncryptionContext()));
        } catch (NotFoundException | DisabledException | InvalidKeyUsageException | KeyUnavailableException
                | KMSInvalidStateException e) {
            throw new RemoteKeySourceException("An exception was thrown from KMS due to invalid key.", e);
        } catch (DependencyTimeoutException | InvalidGrantTokenException | KMSInternalException e) {
            throw new TemporaryJOSEException("A temporary error was thrown from KMS.", e);
        }
    }
}
