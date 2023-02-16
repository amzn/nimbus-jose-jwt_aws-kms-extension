package com.nimbusds.jose.aws.kms.crypto;

import com.amazonaws.services.kms.model.GenerateDataKeyRequest;
import com.amazonaws.services.kms.model.GenerateDataKeyResult;
import com.nimbusds.jose.JOSEException;

public interface KmsGenerateDataKeyOperation {
    GenerateDataKeyResult generateDataKey(GenerateDataKeyRequest request) throws JOSEException;
}
