/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.nimbusds.jose.aws.kms.crypto;


import com.amazonaws.annotation.ThreadSafe;
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
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.aws.kms.crypto.impl.KmsAsymmetricRsaSsaProvider;
import com.nimbusds.jose.util.Base64URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;
import lombok.AllArgsConstructor;
import lombok.NonNull;


/**
 *
 */
@ThreadSafe
@AllArgsConstructor
public class KmsAsymmetricRsaSsaSigner extends KmsAsymmetricRsaSsaProvider implements JWSSigner {

    @NonNull
    private final AWSKMS kms;

    /**
     * KMS Private key ID (it can be a key ID, key ARN, key alias or key alias ARN)
     */
    @NonNull
    private final String privateKeyId;

    /**
     * KMS Message Type.
     */
    @NonNull
    private final MessageType messageType;


    @Override
    public Base64URL sign(final JWSHeader header, final byte[] signingInput) throws JOSEException {

        final var message = getMessage(header, signingInput);
        SignResult signResult;
        try {
            signResult = kms.sign(new SignRequest()
                    .withKeyId(privateKeyId)
                    .withMessageType(messageType)
                    .withMessage(ByteBuffer.wrap(message))
                    .withSigningAlgorithm(header.getAlgorithm().toString()));
        } catch (NotFoundException | DisabledException | KeyUnavailableException | InvalidKeyUsageException e) {
            throw new JOSEException("An exception was thrown from KMS due to invalid key.", e);
        } catch (DependencyTimeoutException | InvalidGrantTokenException | KMSInternalException
                | KMSInvalidStateException e) {
            throw new JOSEException("A temporary exception was thrown from KMS.", e);
        }

        return Base64URL.encode(signResult.getSignature().array());
    }

    private byte[] getMessage(final JWSHeader header, final byte[] signingInput) throws JOSEException {
        final var alg = header.getAlgorithm();
        final var payload = new Payload(signingInput);
        var message = String
                .format("%s.%s", header.toBase64URL(), payload.toBase64URL())
                .getBytes(StandardCharsets.US_ASCII);

        String messageDigestAlgorithm = Optional.ofNullable(JWS_ALGORITHM_TO_MESSAGE_DIGEST_ALGORITHM.get(alg))
                .orElseThrow(() -> new JOSEException(String.format("No algorithm exist for %s in map: %s",
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

        return message;
    }
}
