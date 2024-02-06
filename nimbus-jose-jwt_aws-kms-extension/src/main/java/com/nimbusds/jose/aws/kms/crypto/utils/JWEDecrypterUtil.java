package com.nimbusds.jose.aws.kms.crypto.utils;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.DecryptResult;
import com.amazonaws.services.kms.model.DependencyTimeoutException;
import com.amazonaws.services.kms.model.DisabledException;
import com.amazonaws.services.kms.model.InvalidGrantTokenException;
import com.amazonaws.services.kms.model.InvalidKeyUsageException;
import com.amazonaws.services.kms.model.KMSInternalException;
import com.amazonaws.services.kms.model.KMSInvalidStateException;
import com.amazonaws.services.kms.model.KeyUnavailableException;
import com.amazonaws.services.kms.model.NotFoundException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.RemoteKeySourceException;
import com.nimbusds.jose.aws.kms.exceptions.TemporaryJOSEException;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.jca.JWEJCAContext;
import java.nio.ByteBuffer;
import java.util.Map;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import lombok.experimental.UtilityClass;

/**
 * Utility class containing JWE decryption related methods.
 */
@UtilityClass
public class JWEDecrypterUtil {

    /**
     * Decrypts the specified cipher text of a {@link JWEObject JWE Object}.
     *
     * @throws {@link JOSEException}
     * @throws {@link RemoteKeySourceException}
     * @throws {@link TemporaryJOSEException}
     */
    public byte[] decrypt(
            AWSKMS kms,
            String keyId,
            Map<String, String> encryptionContext,
            JWEHeader header,
            Base64URL encryptedKey,
            Base64URL iv,
            Base64URL cipherText,
            Base64URL authTag,
            JWEJCAContext jcaContext)
            throws JOSEException {

        final DecryptResult cekDecryptResult =
                decryptCek(kms, keyId, encryptionContext, header.getAlgorithm(), encryptedKey);
        final SecretKey cek =
                new SecretKeySpec(cekDecryptResult.getPlaintext().array(), header.getAlgorithm().toString());
        return ContentCryptoProvider.decrypt(header, encryptedKey, iv, cipherText, authTag, cek, jcaContext);
    }

    private DecryptResult decryptCek(
            AWSKMS kms,
            String keyId,
            Map<String, String> encryptionContext,
            JWEAlgorithm alg,
            Base64URL encryptedKey
    ) throws JOSEException {
        try {
            return kms.decrypt(new DecryptRequest()
                    .withEncryptionContext(encryptionContext)
                    .withKeyId(keyId)
                    .withEncryptionAlgorithm(alg.getName())
                    .withCiphertextBlob(ByteBuffer.wrap(encryptedKey.decode())));
        } catch (NotFoundException | DisabledException | InvalidKeyUsageException | KeyUnavailableException
                 | KMSInvalidStateException e) {
            throw new RemoteKeySourceException("An exception was thrown from KMS due to invalid key.", e);
        } catch (DependencyTimeoutException | InvalidGrantTokenException | KMSInternalException e) {
            throw new TemporaryJOSEException("A temporary error was thrown from KMS.", e);
        }
    }
}
