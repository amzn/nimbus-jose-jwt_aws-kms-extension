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

import com.google.common.collect.ImmutableMap;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.impl.BaseJWSProvider;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NonNull;
import lombok.var;
import org.apache.commons.codec.digest.MessageDigestAlgorithms;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Optional;
import java.util.Set;


/**
 * This class provides cryptography support for signing/verification with asymmetric keys stored in AWS KMS.
 */
public abstract class KmsAsymmetricSigningCryptoProvider extends BaseJWSProvider {

    /**
     * AWS-KMS client.
     */
    @NonNull
    @Getter(AccessLevel.PROTECTED)
    private final KmsClient kms;

    /**
     * KMS private-key (CMK) ID (it can be a key ID, key ARN, key alias or key alias ARN)
     */
    @NonNull
    @Getter(AccessLevel.PROTECTED)
    private final String privateKeyId;

    /**
     * KMS Message Type. Refer KMS's sign and verify APIs for details.
     * Ref: <a href="https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html#KMS-Sign-request-MessageType">...</a>
     */
    @NonNull
    @Getter(AccessLevel.PROTECTED)
    private final MessageType messageType;

    public static final Map<JWSAlgorithm, String> JWS_ALGORITHM_TO_MESSAGE_DIGEST_ALGORITHM =
            ImmutableMap.<JWSAlgorithm, String>builder()
                    .put(JWSAlgorithm.RS256, MessageDigestAlgorithms.SHA_256)
                    .put(JWSAlgorithm.RS384, MessageDigestAlgorithms.SHA_384)
                    .put(JWSAlgorithm.RS512, MessageDigestAlgorithms.SHA_512)
                    .put(JWSAlgorithm.PS256, MessageDigestAlgorithms.SHA_256)
                    .put(JWSAlgorithm.PS384, MessageDigestAlgorithms.SHA_384)
                    .put(JWSAlgorithm.PS512, MessageDigestAlgorithms.SHA_512)
                    .put(JWSAlgorithm.ES256, MessageDigestAlgorithms.SHA_256)
                    .put(JWSAlgorithm.ES384, MessageDigestAlgorithms.SHA_384)
                    .put(JWSAlgorithm.ES512, MessageDigestAlgorithms.SHA_512)
                    // backwards compatibility for KMS-defined algorithm strings
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
                    .put(JWSAlgorithm.parse(SigningAlgorithmSpec.ECDSA_SHA_256.toString()),
                            MessageDigestAlgorithms.SHA_256)
                    .put(JWSAlgorithm.parse(SigningAlgorithmSpec.ECDSA_SHA_384.toString()),
                            MessageDigestAlgorithms.SHA_384)
                    .put(JWSAlgorithm.parse(SigningAlgorithmSpec.ECDSA_SHA_512.toString()),
                            MessageDigestAlgorithms.SHA_512)
                    .build();

    public static final Map<JWSAlgorithm, SigningAlgorithmSpec> JWS_ALGORITHM_TO_SIGNING_ALGORITHM_SPEC =
            ImmutableMap.<JWSAlgorithm, SigningAlgorithmSpec>builder()
                    .put(JWSAlgorithm.RS256, SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256)
                    .put(JWSAlgorithm.RS384, SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_384)
                    .put(JWSAlgorithm.RS512, SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_512)
                    .put(JWSAlgorithm.PS256, SigningAlgorithmSpec.RSASSA_PSS_SHA_256)
                    .put(JWSAlgorithm.PS384, SigningAlgorithmSpec.RSASSA_PSS_SHA_384)
                    .put(JWSAlgorithm.PS512, SigningAlgorithmSpec.RSASSA_PSS_SHA_512)
                    .put(JWSAlgorithm.ES256, SigningAlgorithmSpec.ECDSA_SHA_256)
                    .put(JWSAlgorithm.ES384, SigningAlgorithmSpec.ECDSA_SHA_384)
                    .put(JWSAlgorithm.ES512, SigningAlgorithmSpec.ECDSA_SHA_512)
                    // Compatibility for KMS-defined algorithm strings
                    .put(JWSAlgorithm.parse(SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256.toString()),
                            SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256)
                    .put(JWSAlgorithm.parse(SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_384.toString()),
                            SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_384)
                    .put(JWSAlgorithm.parse(SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_512.toString()),
                            SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_512)
                    .put(JWSAlgorithm.parse(SigningAlgorithmSpec.RSASSA_PSS_SHA_256.toString()),
                            SigningAlgorithmSpec.RSASSA_PSS_SHA_256)
                    .put(JWSAlgorithm.parse(SigningAlgorithmSpec.RSASSA_PSS_SHA_384.toString()),
                            SigningAlgorithmSpec.RSASSA_PSS_SHA_384)
                    .put(JWSAlgorithm.parse(SigningAlgorithmSpec.RSASSA_PSS_SHA_512.toString()),
                            SigningAlgorithmSpec.RSASSA_PSS_SHA_512)
                    .put(JWSAlgorithm.parse(SigningAlgorithmSpec.ECDSA_SHA_256.toString()),
                            SigningAlgorithmSpec.ECDSA_SHA_256)
                    .put(JWSAlgorithm.parse(SigningAlgorithmSpec.ECDSA_SHA_384.toString()),
                            SigningAlgorithmSpec.ECDSA_SHA_384)
                    .put(JWSAlgorithm.parse(SigningAlgorithmSpec.ECDSA_SHA_512.toString()),
                            SigningAlgorithmSpec.ECDSA_SHA_512)
                    .build();
    /**
     * The supported JWS algorithms (alg).
     * <p>
     * Note: We accept both the algorithms defined in RFC-7518 and KMS-defined strings.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-3.1">RFC-7518 Section 3.1</a>
     * @see <a href="https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html">
     * AWS Developer Guide - Asymmetric key specs
     * </a>
     */
    public static final Set<JWSAlgorithm> SUPPORTED_ALGORITHMS = JWS_ALGORITHM_TO_SIGNING_ALGORITHM_SPEC.keySet();

    protected KmsAsymmetricSigningCryptoProvider(
            @NonNull final KmsClient kms, @NonNull final String privateKeyId, @NonNull final MessageType messageType) {
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
                        String.format("No digest algorithm exist for the JWS algorithm %s in map: %s",
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
