/*
  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

  Licensed under the Apache License, Version 2.0 (the "License").
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 */

package com.nimbusds.jose.aws.kms.crypto;

import com.amazonaws.services.kms.AWSKMS;
import com.nimbusds.jose.CriticalHeaderParamsAware;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.aws.kms.crypto.impl.KmsSymmetricCryptoProvider;
import com.nimbusds.jose.aws.kms.crypto.utils.JWEDecrypterUtil;
import com.nimbusds.jose.crypto.impl.CriticalHeaderParamsDeferral;
import com.nimbusds.jose.util.Base64URL;
import java.util.Map;
import java.util.Set;
import javax.annotation.concurrent.ThreadSafe;
import lombok.NonNull;

/**
 * Decrypter implementation for SYMMETRIC (AES based) signing with public/private key stored in AWS KMS.
 * <p>
 * See {@link KmsSymmetricCryptoProvider} for supported algorithms and encryption methods, and for details of various
 * constructor parameters.
 */
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
        this(kms, keyId);
        critPolicy.setDeferredCriticalHeaderParams(defCritHeaders);
    }

    public KmsSymmetricDecrypter(@NonNull final AWSKMS kms, @NonNull final String keyId,
            @NonNull final Map<String, String> encryptionContext, @NonNull final Set<String> defCritHeaders) {
        this(kms, keyId, encryptionContext);
        critPolicy.setDeferredCriticalHeaderParams(defCritHeaders);
    }

    @Override
    public Set<String> getProcessedCriticalHeaderParams() {
        return critPolicy.getProcessedCriticalHeaderParams();
    }

    @Override
    public Set<String> getDeferredCriticalHeaderParams() {
        return critPolicy.getDeferredCriticalHeaderParams();
    }

    @Override
    public byte[] decrypt(
            @NonNull final JWEHeader header,
            @NonNull final Base64URL encryptedKey,
            @NonNull final Base64URL iv,
            @NonNull final Base64URL cipherText,
            @NonNull final Base64URL authTag)
            throws JOSEException {

        validateJWEHeader(header);
        critPolicy.ensureHeaderPasses(header);

        return JWEDecrypterUtil.decrypt(getKms(), getKeyId(), getEncryptionContext(), header, encryptedKey, iv,
                cipherText, authTag, getJCAContext());
    }
}
