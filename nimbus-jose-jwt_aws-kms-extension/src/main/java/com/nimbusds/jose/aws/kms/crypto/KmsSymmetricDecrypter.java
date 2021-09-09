package com.nimbusds.jose.aws.kms.crypto;

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
import com.nimbusds.jose.CriticalHeaderParamsAware;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.aws.kms.crypto.impl.KmsSymmetricCryptoProvider;
import com.nimbusds.jose.crypto.impl.AlgorithmSupportMessage;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.crypto.impl.CriticalHeaderParamsDeferral;
import com.nimbusds.jose.util.Base64URL;
import java.nio.ByteBuffer;
import java.util.Map;
import java.util.Set;
import javax.annotation.concurrent.ThreadSafe;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import lombok.NonNull;

@ThreadSafe
public class KmsSymmetricDecrypter extends KmsSymmetricCryptoProvider implements JWEDecrypter,
        CriticalHeaderParamsAware {

    /**
     * The critical header policy.
     */
    private final CriticalHeaderParamsDeferral critPolicy = new CriticalHeaderParamsDeferral();


    public KmsSymmetricDecrypter(@NonNull final AWSKMS kms, @NonNull final String keyId,
            @NonNull final Map<String, String> encryptionContext) {
        super(kms, keyId, encryptionContext);
    }


    public KmsSymmetricDecrypter(@NonNull final AWSKMS kms, @NonNull final String keyId) {
        super(kms, keyId);
    }


    public KmsSymmetricDecrypter(@NonNull final AWSKMS kms, @NonNull final String keyId,
            @NonNull final Set<String> defCritHeaders) {
        super(kms, keyId);
        critPolicy.setDeferredCriticalHeaderParams(defCritHeaders);
    }


    public KmsSymmetricDecrypter(@NonNull final AWSKMS kms, @NonNull final String keyId,
            @NonNull final Map<String, String> encryptionContext, @NonNull final Set<String> defCritHeaders) {
        super(kms, keyId, encryptionContext);
        critPolicy.setDeferredCriticalHeaderParams(defCritHeaders);
    }


    @Override
    public Set<String> getProcessedCriticalHeaderParams() {

        return critPolicy.getProcessedCriticalHeaderParams();
    }


    @Override
    public Set<String> getDeferredCriticalHeaderParams() {

        return critPolicy.getProcessedCriticalHeaderParams();
    }


    @Override
    public byte[] decrypt(final JWEHeader header,
            final Base64URL encryptedKey,
            final Base64URL iv,
            final Base64URL cipherText,
            final Base64URL authTag)
            throws JOSEException {

        // Validate required JWE parts
        if (encryptedKey == null) {
            throw new JOSEException("Missing JWE encrypted key");
        }

        if (iv == null) {
            throw new JOSEException("Missing JWE initialization vector (IV)");
        }

        final JWEAlgorithm alg = header.getAlgorithm();

        if (!SUPPORTED_ALGORITHMS.contains(alg)) {
            throw new JOSEException(AlgorithmSupportMessage.unsupportedJWEAlgorithm(alg, SUPPORTED_ALGORITHMS));
        }

        critPolicy.ensureHeaderPasses(header);

        final DecryptResult cekDecryptResult =
                decryptCek(getKeyId(), getEncryptionContext(), encryptedKey);
        final SecretKey cek =
                new SecretKeySpec(cekDecryptResult.getPlaintext().array(), header.getAlgorithm().toString());

        return ContentCryptoProvider.decrypt(header, encryptedKey, iv, cipherText, authTag, cek, getJCAContext());
    }

    private DecryptResult decryptCek(String keyId, Map<String, String> encryptionContext, Base64URL encryptedKey)
            throws JOSEException {
        try {
            return getKms().decrypt(buildDecryptRequest(keyId, encryptionContext, encryptedKey));
        } catch (NotFoundException | DisabledException | InvalidKeyUsageException | KeyUnavailableException
                | KMSInvalidStateException e) {
            throw new JOSEException("An error occurred while using Key", e);
        } catch (DependencyTimeoutException | InvalidGrantTokenException
                | KMSInternalException e) {
            throw new JOSEException("A temporary error was thrown from KMS.", e);
        }
    }

    private DecryptRequest buildDecryptRequest(String keyId, Map<String, String> encryptionContext,
            Base64URL encryptedKey) {
        return new DecryptRequest()
                .withEncryptionContext(encryptionContext)
                .withKeyId(keyId)
                .withCiphertextBlob(ByteBuffer.wrap(encryptedKey.decode()));
    }

}
