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
import com.nimbusds.jose.aws.kms.crypto.impl.KmsAsymmetricRsaSsaProvider;
import com.nimbusds.jose.util.Base64URL;
import lombok.NonNull;


/**
 *
 */
@ThreadSafe
public class KmsAsymmetricRsaSsaSigner extends KmsAsymmetricRsaSsaProvider implements JWSSigner {

    public KmsAsymmetricRsaSsaSigner(
            @NonNull final AWSKMS kms, @NonNull final String privateKeyId, @NonNull final MessageType messageType) {
        super(kms, privateKeyId, messageType);
    }

    @Override
    public Base64URL sign(final JWSHeader header, final byte[] signingInput) throws JOSEException {

        final var message = getMessage(header, signingInput);
        SignResult signResult;
        try {
            signResult = getKms().sign(new SignRequest()
                    .withKeyId(getPrivateKeyId())
                    .withMessageType(getMessageType())
                    .withMessage(message)
                    .withSigningAlgorithm(header.getAlgorithm().toString()));
        } catch (NotFoundException | DisabledException | KeyUnavailableException | InvalidKeyUsageException e) {
            throw new JOSEException("An exception was thrown from KMS due to invalid key.", e);
        } catch (DependencyTimeoutException | InvalidGrantTokenException | KMSInternalException
                | KMSInvalidStateException e) {
            throw new JOSEException("A temporary exception was thrown from KMS.", e);
        }

        return Base64URL.encode(signResult.getSignature().array());
    }
}
