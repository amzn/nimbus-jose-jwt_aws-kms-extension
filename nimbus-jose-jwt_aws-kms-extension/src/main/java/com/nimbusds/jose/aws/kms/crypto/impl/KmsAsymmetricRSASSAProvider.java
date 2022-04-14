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
import com.amazonaws.services.kms.model.MessageType;
import com.amazonaws.services.kms.model.SigningAlgorithmSpec;
import com.google.common.collect.ImmutableMap;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.impl.BaseJWSProvider;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NonNull;
import lombok.var;
import org.apache.commons.codec.digest.MessageDigestAlgorithms;


/**
 * This class provides cryptography support for RSA-SSA based signing/verification with keys stored in AWS KMS.
 */
public abstract class KmsAsymmetricRSASSAProvider extends BaseJWSProvider {

    /**
     * AWS-KMS client.
     */
    @NonNull
    @Getter(AccessLevel.PROTECTED)
    private final AWSKMS kms;

    /**
     * KMS private-key (CMK) ID (it can be a key ID, key ARN, key alias or key alias ARN)
     */
    @NonNull
    @Getter(AccessLevel.PROTECTED)
    private final String privateKeyId;

    /**
     * KMS Message Type. Refer KMS's sign and verify APIs for details.
     * Ref: https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html#KMS-Sign-request-MessageType
     */
    @NonNull
    @Getter(AccessLevel.PROTECTED)
    private final MessageType messageType;

    public static final Map<JWSAlgorithm, String> JWS_ALGORITHM_TO_MESSAGE_DIGEST_ALGORITHM =
            ImmutableMap.<JWSAlgorithm, String>builder()
                    .put(JWSAlgorithm.parse(SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256.toString()),
                            MessageDigestAlgorithms.SHA_256)
                    .put(JWSAlgorithm.parse(SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_384.toString()),
                            MessageDigestAlgorithms.SHA_384)
                    .put(JWSAlgorithm.parse(SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_512.toString()),
                            MessageDigestAlgorithms.SHA_512)
                    .put(JWSAlgorithm.parse(SigningAlgorithmSpec.RSASSA_PSS_SHA_256.toString()),
                            MessageDigestAlgorithms.SHA_256)
                    .put(JWSAlgorithm.parse(SigningAlgorithmSpec.RSASSA_PSS_SHA_384.toString()),
                            MessageDigestAlgorithms.SHA_384)
                    .put(JWSAlgorithm.parse(SigningAlgorithmSpec.RSASSA_PSS_SHA_512.toString()),
                            MessageDigestAlgorithms.SHA_512)
                    .build();

    /**
     * The supported JWS algorithms (alg) by the RSA-SSA provider class.
     *
     * Note: We are using KMS prescribed algorithm names here.
     * Ref: https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose.html#key-spec-rsa-sign
     */
    public static final Set<JWSAlgorithm> SUPPORTED_ALGORITHMS = JWS_ALGORITHM_TO_MESSAGE_DIGEST_ALGORITHM.keySet();

    protected KmsAsymmetricRSASSAProvider(
            @NonNull final AWSKMS kms, @NonNull final String privateKeyId, @NonNull final MessageType messageType) {
        super(SUPPORTED_ALGORITHMS);
        this.kms = kms;
        this.privateKeyId = privateKeyId;
        this.messageType = messageType;
    }

    protected ByteBuffer getMessage(final JWSHeader header, final byte[] signingInput) throws JOSEException {
        final var alg = header.getAlgorithm();
        var message = signingInput;

        String messageDigestAlgorithm = Optional.ofNullable(JWS_ALGORITHM_TO_MESSAGE_DIGEST_ALGORITHM.get(alg))
                .orElseThrow(() -> new JOSEException(
                        String.format("No digest algorithm exist for JWE algorithm %s in map: %s",
                                alg, JWS_ALGORITHM_TO_MESSAGE_DIGEST_ALGORITHM)));

        if (messageType == MessageType.DIGEST) {
            MessageDigest messageDigestProvider;
            try {
                messageDigestProvider = MessageDigest.getInstance(messageDigestAlgorithm);
            } catch (NoSuchAlgorithmException e) {
                throw new JOSEException("Invalid message digest algorithm.", e);
            }
            message = messageDigestProvider.digest(message);
        }

        return ByteBuffer.wrap(message);
    }
}
