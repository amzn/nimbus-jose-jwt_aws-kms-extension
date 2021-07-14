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
import com.nimbusds.jose.KeyException;
import com.nimbusds.jose.crypto.impl.AlgorithmSupportMessage;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.crypto.impl.CriticalHeaderParamsDeferral;
import com.nimbusds.jose.util.Base64URL;
import java.nio.ByteBuffer;
import java.util.Map;
import java.util.Set;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import lombok.NonNull;

public class KmsSymmetricDecrypter extends KmsSymmetricCryptoProvider implements JWEDecrypter,
        CriticalHeaderParamsAware {

    @NonNull
    private final AWSKMS kms;
    /**
     * The critical header policy.
     */
    private final CriticalHeaderParamsDeferral critPolicy = new CriticalHeaderParamsDeferral();

    public KmsSymmetricDecrypter(final AWSKMS kms) {
        this(kms, null);
    }

    public KmsSymmetricDecrypter(final AWSKMS kms, final Set<String> defCritHeaders) {

        super();
        this.kms = kms;
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

        DecryptResult decryptResult = generateDecryptResult(header.getKeyID(),
                header.getCustomParam(KmsSymmetricCryptoProvider.ENCRYPTION_CONTEXT_HEADER),
                encryptedKey);

        final SecretKey cek = new SecretKeySpec(decryptResult.getPlaintext().array(), header.getAlgorithm().toString());
        return ContentCryptoProvider.decrypt(header, encryptedKey, iv, cipherText, authTag, cek, getJCAContext());
    }

    private DecryptResult generateDecryptResult(String keyId, Object encryptionContext, Base64URL encryptedKey)
            throws JOSEException {
        try {
            return kms.decrypt(buildDecryptRequest(keyId, encryptionContext, encryptedKey));
        } catch (NotFoundException | DisabledException | InvalidKeyUsageException | KeyUnavailableException
                | KMSInvalidStateException e) {
            throw new KeyException("An error occurred while using Key");
        } catch (DependencyTimeoutException | InvalidGrantTokenException
                | KMSInternalException e) {
            throw new JOSEException("A temporary error was thrown from KMS.");
        }
    }

    private DecryptRequest buildDecryptRequest(String keyId, Object encryptionContext, Base64URL encryptedKey) {
        return new DecryptRequest()
                .withEncryptionContext(Map.of(ENCRYPTION_CONTEXT_HEADER, encryptionContext.toString()))
                .withKeyId(keyId)
                .withCiphertextBlob(ByteBuffer.wrap(encryptedKey.decode()));
    }

}
