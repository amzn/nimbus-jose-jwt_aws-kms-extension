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


import com.nimbusds.jose.aws.kms.crypto.impl.KmsAsymmetricRSASSAProvider;
import lombok.NonNull;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.MessageType;

import javax.annotation.concurrent.ThreadSafe;
import java.util.Set;

/**
 * Sign verifier implementation for RSA-SSA signing with public/private key stored in AWS KMS.
 * <p>
 * See {@link KmsAsymmetricRSASSAProvider} for supported algorithms, and for details of various
 * constructor parameters.
 *
 * @deprecated use {@link KmsAsymmetricVerifier} instead.
 */
@ThreadSafe
@Deprecated
public class KmsAsymmetricRSASSAVerifier extends KmsAsymmetricVerifier {

    public KmsAsymmetricRSASSAVerifier(
            @NonNull final KmsClient kms, @NonNull final String privateKeyId, @NonNull final MessageType messageType) {
        super(kms, privateKeyId, messageType);
    }

    public KmsAsymmetricRSASSAVerifier(
            @NonNull final KmsClient kms, @NonNull String privateKeyId, @NonNull final MessageType messageType,
            @NonNull final Set<String> defCritHeaders) {
        super(kms, privateKeyId, messageType, defCritHeaders);
    }
}
