package com.nimbusds.jose.aws.kms.crypto;

import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.DecryptResult;
import com.nimbusds.jose.JOSEException;

public interface KmsDecryptOperation {
    DecryptResult decrypt(DecryptRequest decryptRequest) throws JOSEException;
}
