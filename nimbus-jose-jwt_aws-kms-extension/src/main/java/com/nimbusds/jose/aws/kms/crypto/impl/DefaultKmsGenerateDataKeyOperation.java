package com.nimbusds.jose.aws.kms.crypto.impl;

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
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.RemoteKeySourceException;
import com.nimbusds.jose.aws.kms.crypto.KmsGenerateDataKeyOperation;
import com.nimbusds.jose.aws.kms.exceptions.TemporaryJOSEException;
import lombok.AllArgsConstructor;
import lombok.NonNull;

@AllArgsConstructor
public class DefaultKmsGenerateDataKeyOperation implements KmsGenerateDataKeyOperation {

    @NonNull
    private final AWSKMS kms;

    @Override
    public GenerateDataKeyResult generateDataKey(GenerateDataKeyRequest request)
            throws JOSEException {
        try {
            return kms.generateDataKey(request);
        } catch (NotFoundException | DisabledException | InvalidKeyUsageException | KeyUnavailableException
                 | KMSInvalidStateException e) {
            throw new RemoteKeySourceException("An exception was thrown from KMS due to invalid key.", e);
        } catch (DependencyTimeoutException | InvalidGrantTokenException | KMSInternalException e) {
            throw new TemporaryJOSEException("A temporary error was thrown from KMS.", e);
        }
    }
}
