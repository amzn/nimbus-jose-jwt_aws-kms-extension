package com.nimbusds.jose.aws.kms.crypto.utils;

import com.nimbusds.jose.*;
import com.nimbusds.jose.aws.kms.exceptions.TemporaryJOSEException;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.jca.JWEJCAContext;
import com.nimbusds.jose.util.Base64URL;
import lombok.experimental.UtilityClass;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.*;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Map;

/**
 * Utility class containing JWE decryption related methods.
 */
@UtilityClass
public class JWEDecrypterUtil {

    /**
     * Decrypts the specified cipher text of a {@link JWEObject JWE Object}.
     *
     * @throws RemoteKeySourceException in case exception is thrown from KMS due to invalid key
     * @throws TemporaryJOSEException   in case temporary error is thrown from KMS
     */
    public byte[] decrypt(
            KmsClient kms,
            String keyId,
            Map<String, String> encryptionContext,
            JWEHeader header,
            Base64URL encryptedKey,
            Base64URL iv,
            Base64URL cipherText,
            Base64URL authTag,
            JWEJCAContext jcaContext)
            throws JOSEException {

        final DecryptResponse cekDecryptResult =
                decryptCek(kms, keyId, encryptionContext, header.getAlgorithm(), encryptedKey);
        final SecretKey cek =
                new SecretKeySpec(cekDecryptResult.plaintext().asByteArray(), header.getAlgorithm().toString());
        return ContentCryptoProvider.decrypt(header, encryptedKey, iv, cipherText, authTag, cek, jcaContext);
    }

    private DecryptResponse decryptCek(
            KmsClient kms,
            String keyId,
            Map<String, String> encryptionContext,
            JWEAlgorithm alg,
            Base64URL encryptedKey
    ) throws JOSEException {
        try {
            return kms.decrypt(DecryptRequest.builder()
                    .encryptionContext(encryptionContext)
                    .keyId(keyId)
                    .encryptionAlgorithm(alg.getName())
                    .ciphertextBlob(SdkBytes.fromByteArray(encryptedKey.decode()))
                    .build());
        } catch (NotFoundException | DisabledException | InvalidKeyUsageException | KeyUnavailableException
                 | KmsInvalidStateException e) {
            throw new RemoteKeySourceException("An exception was thrown from KMS due to invalid key.", e);
        } catch (DependencyTimeoutException | InvalidGrantTokenException | KmsInternalException e) {
            throw new TemporaryJOSEException("A temporary error was thrown from KMS.", e);
        }
    }
}
