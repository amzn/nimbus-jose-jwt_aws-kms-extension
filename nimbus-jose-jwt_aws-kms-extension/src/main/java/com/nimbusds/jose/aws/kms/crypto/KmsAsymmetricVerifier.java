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


import com.nimbusds.jose.*;
import com.nimbusds.jose.aws.kms.crypto.impl.KmsAsymmetricSigningCryptoProvider;
import com.nimbusds.jose.aws.kms.exceptions.TemporaryJOSEException;
import com.nimbusds.jose.crypto.impl.CriticalHeaderParamsDeferral;
import com.nimbusds.jose.util.Base64URL;
import lombok.NonNull;
import lombok.var;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.*;

import javax.annotation.concurrent.ThreadSafe;
import java.nio.ByteBuffer;
import java.util.Set;

/**
 * Sign verifier implementation for asymmetric signing with public/private key stored in AWS KMS.
 * <p>
 * See {@link KmsAsymmetricSigningCryptoProvider} for supported algorithms, and for details of various
 * constructor parameters.
 */
@ThreadSafe
public class KmsAsymmetricVerifier extends KmsAsymmetricSigningCryptoProvider implements JWSVerifier, CriticalHeaderParamsAware {

    /**
     * The critical header policy.
     */
    private final CriticalHeaderParamsDeferral critPolicy = new CriticalHeaderParamsDeferral();


    public KmsAsymmetricVerifier(
            @NonNull final KmsClient kms, @NonNull final String privateKeyId, @NonNull final MessageType messageType) {
        super(kms, privateKeyId, messageType);
    }


    public KmsAsymmetricVerifier(
            @NonNull final KmsClient kms, @NonNull String privateKeyId, @NonNull final MessageType messageType,
            @NonNull final Set<String> defCritHeaders) {
        super(kms, privateKeyId, messageType);
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
    public boolean verify(
            @NonNull final JWSHeader header, @NonNull final byte[] signedContent, @NonNull final Base64URL signature)
            throws JOSEException {

        if (!critPolicy.headerPasses(header)) {
            return false;
        }

        var message = getMessage(header, signedContent);

        VerifyResponse verifyResponse;
        try {
            verifyResponse = getKms().verify(VerifyRequest.builder()
                    .keyId(getPrivateKeyId())
                    .signingAlgorithm(JWS_ALGORITHM_TO_SIGNING_ALGORITHM_SPEC.get(header.getAlgorithm()).toString())
                    .messageType(getMessageType())
                    .message(SdkBytes.fromByteBuffer(message))
                    .signature(SdkBytes.fromByteBuffer(ByteBuffer.wrap(signature.decode())))
                    .build());
        } catch (KmsInvalidSignatureException e) {
            return false;
        } catch (NotFoundException | DisabledException | KeyUnavailableException | InvalidKeyUsageException
                 | KmsInvalidStateException e) {
            throw new RemoteKeySourceException("An exception was thrown from KMS due to invalid key.", e);
        } catch (DependencyTimeoutException | InvalidGrantTokenException | KmsInternalException e) {
            throw new TemporaryJOSEException("A temporary exception was thrown from KMS.", e);
        }

        return verifyResponse.signatureValid();
    }

}
