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

package com.nimbusds.jose.aws.kms.crypto.impl;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.DataKeySpec;
import com.amazonaws.services.kms.model.EncryptionAlgorithmSpec;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.aws.kms.crypto.utils.JWEHeaderUtil;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.crypto.impl.PublicBaseJWEProvider;
import java.util.Map;
import java.util.Set;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NonNull;


/**
 * This class provides cryptography support for SYMMETRIC (AES based) encryption/decryption with keys stored in AWS
 * KMS.
 */
public abstract class KmsSymmetricCryptoProvider extends PublicBaseJWEProvider {

    /**
     * AWS-KMS client.
     */
    @NonNull
    @Getter(AccessLevel.PROTECTED)
    private final AWSKMS kms;

    /**
     * KMS key (CMK) ID (it can be a key ID, key ARN, key alias or key alias ARN)
     */
    @NonNull
    @Getter(AccessLevel.PROTECTED)
    private final String keyId;

    /**
     * Encryption context for KMS. Refer KMS's encrypt and decrypt APIs for more details.
     * Ref: https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html#KMS-Encrypt-request-EncryptionContext
     */
    @Getter(AccessLevel.PROTECTED)
    private Map<String, String> encryptionContext;

    /**
     * The supported JWE algorithms (alg) by the AWS crypto provider class.
     *
     * Note: We are using KMS prescribed algorithm names here.
     * Ref: https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose.html#key-spec-symmetric-default
     */
    public static final Set<JWEAlgorithm> SUPPORTED_ALGORITHMS = ImmutableSet.of(
            JWEAlgorithm.parse(EncryptionAlgorithmSpec.SYMMETRIC_DEFAULT.toString()));

    /**
     * The supported JWE encryption methods (enc) by the AWS crypto provider class.
     *
     * Note: We are using JWE prescribed encryption method names here.
     */
    public static final Set<EncryptionMethod> SUPPORTED_ENCRYPTION_METHODS = ImmutableSet.of(
            EncryptionMethod.A128CBC_HS256,
            EncryptionMethod.A256CBC_HS512,
            EncryptionMethod.A128GCM,
            EncryptionMethod.A256GCM);

    public static final Map<EncryptionMethod, DataKeySpec> ENCRYPTION_METHOD_TO_DATA_KEY_SPEC_MAP =
            ImmutableMap.<EncryptionMethod, DataKeySpec>builder()
                    .put(EncryptionMethod.A256GCM, DataKeySpec.AES_256)
                    .put(EncryptionMethod.A256CBC_HS512, DataKeySpec.AES_256)
                    .put(EncryptionMethod.A128GCM, DataKeySpec.AES_128)
                    .put(EncryptionMethod.A128CBC_HS256, DataKeySpec.AES_128)
                    .build();

    public static final String ENCRYPTION_CONTEXT_HEADER = "ec";

    protected KmsSymmetricCryptoProvider(@NonNull final AWSKMS kms, @NonNull final String keyId) {
        super(SUPPORTED_ALGORITHMS, ContentCryptoProvider.SUPPORTED_ENCRYPTION_METHODS);
        this.kms = kms;
        this.keyId = keyId;
    }

    protected KmsSymmetricCryptoProvider(@NonNull final AWSKMS kms, @NonNull final String keyId,
            @NonNull final Map<String, String> encryptionContext) {
        this(kms, keyId);
        this.encryptionContext = ImmutableMap.copyOf(encryptionContext);
    }

    protected void validateJWEHeader(@NonNull final JWEHeader header) throws JOSEException {
        JWEHeaderUtil.validateJWEHeaderAlgorithms(header, SUPPORTED_ALGORITHMS, SUPPORTED_ENCRYPTION_METHODS);
    }
}
