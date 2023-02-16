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
import com.amazonaws.services.kms.model.GenerateDataKeyRequest;
import com.amazonaws.services.kms.model.GenerateDataKeyResult;
import com.google.common.collect.ImmutableMap;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWECryptoParts;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.aws.kms.crypto.impl.DefaultKmsGenerateDataKeyOperation;
import com.nimbusds.jose.aws.kms.crypto.impl.KmsSymmetricCryptoProvider;
import com.nimbusds.jose.aws.kms.crypto.impl.LoadingCachedKmsGenerateDataKeyOperation;
import com.nimbusds.jose.aws.kms.crypto.impl.models.CacheConfiguration;
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

    @NonNull
    private final KmsGenerateDataKeyOperation kmsGenerateDataKeyOperation;

    public KmsSymmetricEncrypter(@NonNull final AWSKMS kms, @NonNull final String keyId) {
        this(kms, keyId, new DefaultKmsGenerateDataKeyOperation(kms));
    }

    public KmsSymmetricEncrypter(@NonNull final AWSKMS kms, @NonNull final String keyId,
            @NonNull final CacheConfiguration cacheConfiguration) {
        this(kms, keyId,
                new LoadingCachedKmsGenerateDataKeyOperation(
                        new DefaultKmsGenerateDataKeyOperation(kms), cacheConfiguration));
    }

    public KmsSymmetricEncrypter(@NonNull final AWSKMS kms, @NonNull final String keyId,
            @NonNull final KmsGenerateDataKeyOperation kmsGenerateDataKeyOperation) {
        super(kms, keyId);
        this.kmsGenerateDataKeyOperation = kmsGenerateDataKeyOperation;
    }

    public KmsSymmetricEncrypter(@NonNull final AWSKMS kms, @NonNull final String keyId,
            @NonNull final Map<String, String> encryptionContext) {
        this(kms, keyId, encryptionContext, new DefaultKmsGenerateDataKeyOperation(kms));
    }

    public KmsSymmetricEncrypter(@NonNull final AWSKMS kms, @NonNull final String keyId,
            @NonNull final Map<String, String> encryptionContext,
            @NonNull final CacheConfiguration cacheConfiguration) {
        this(kms, keyId, encryptionContext, new LoadingCachedKmsGenerateDataKeyOperation(
                new DefaultKmsGenerateDataKeyOperation(kms), cacheConfiguration);
    }

    public KmsSymmetricEncrypter(@NonNull final AWSKMS kms, @NonNull final String keyId,
            @NonNull final Map<String, String> encryptionContext,
            @NonNull final KmsGenerateDataKeyOperation kmsGenerateDataKeyOperation) {
        super(kms, keyId, encryptionContext);
        this.kmsGenerateDataKeyOperation = kmsGenerateDataKeyOperation;
    }

    @Override
    public JWECryptoParts encrypt(@NonNull final JWEHeader header, @NonNull final byte[] clearText)
            throws JOSEException {

        validateJWEHeader(header);

        final JWEHeader updatedHeader; // We need to work on the header
        final Base64URL encryptedKey; // The second JWE part

        // Generate and encrypt the CEK according to the enc method
        GenerateDataKeyResult generateDataKeyResult = kmsGenerateDataKeyOperation
                .generateDataKey(new GenerateDataKeyRequest()
                        .withKeyId(getKeyId())
                        .withKeySpec(ENCRYPTION_METHOD_TO_DATA_KEY_SPEC_MAP.get(header.getEncryptionMethod()))
                        .withEncryptionContext(getEncryptionContext()));
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
}
