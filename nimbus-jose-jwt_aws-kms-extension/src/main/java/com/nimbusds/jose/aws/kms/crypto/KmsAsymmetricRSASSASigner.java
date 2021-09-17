package com.nimbusds.jose.aws.kms.crypto;


import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.DependencyTimeoutException;
import com.amazonaws.services.kms.model.DisabledException;
import com.amazonaws.services.kms.model.InvalidGrantTokenException;
import com.amazonaws.services.kms.model.InvalidKeyUsageException;
import com.amazonaws.services.kms.model.KMSInternalException;
import com.amazonaws.services.kms.model.KMSInvalidStateException;
import com.amazonaws.services.kms.model.KeyUnavailableException;
import com.amazonaws.services.kms.model.MessageType;
import com.amazonaws.services.kms.model.NotFoundException;
import com.amazonaws.services.kms.model.SignRequest;
import com.amazonaws.services.kms.model.SignResult;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.RemoteKeySourceException;
import com.nimbusds.jose.aws.kms.crypto.impl.KmsAsymmetricRSASSAProvider;
import com.nimbusds.jose.aws.kms.exceptions.TemporaryJOSEException;
import com.nimbusds.jose.util.Base64URL;
import javax.annotation.concurrent.ThreadSafe;
import lombok.NonNull;
import lombok.var;


/**
 *
 */
@ThreadSafe
public class KmsAsymmetricRSASSASigner extends KmsAsymmetricRSASSAProvider implements JWSSigner {

    public KmsAsymmetricRSASSASigner(
            @NonNull final AWSKMS kms, @NonNull final String privateKeyId, @NonNull final MessageType messageType) {
        super(kms, privateKeyId, messageType);
    }

    @Override
    public Base64URL sign(@NonNull final JWSHeader header, @NonNull final byte[] signingInput) throws JOSEException {

        final var message = getMessage(header, signingInput);
        SignResult signResult;
        try {
            signResult = getKms().sign(new SignRequest()
                    .withKeyId(getPrivateKeyId())
                    .withMessageType(getMessageType())
                    .withMessage(message)
                    .withSigningAlgorithm(header.getAlgorithm().toString()));
        } catch (NotFoundException | DisabledException | KeyUnavailableException | InvalidKeyUsageException
                | KMSInvalidStateException e) {
            throw new RemoteKeySourceException("An exception was thrown from KMS due to invalid key.", e);
        } catch (DependencyTimeoutException | InvalidGrantTokenException | KMSInternalException e) {
            throw new TemporaryJOSEException("A temporary exception was thrown from KMS.", e);
        }

        return Base64URL.encode(signResult.getSignature().array());
    }
}
