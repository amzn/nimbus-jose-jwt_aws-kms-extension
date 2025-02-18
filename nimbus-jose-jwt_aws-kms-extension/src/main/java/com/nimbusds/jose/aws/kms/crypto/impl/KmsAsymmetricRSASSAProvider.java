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

import lombok.NonNull;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.MessageType;


/**
 * This class provides cryptography support for RSA-SSA based signing/verification with keys stored in AWS KMS.
 *
 * @deprecated use {@link KmsAsymmetricSigningCryptoProvider} instead.
 */
@Deprecated
public abstract class KmsAsymmetricRSASSAProvider extends KmsAsymmetricSigningCryptoProvider {
    protected KmsAsymmetricRSASSAProvider(
            @NonNull final KmsClient kms, @NonNull final String privateKeyId, @NonNull final MessageType messageType) {
        super(kms, privateKeyId, messageType);
    }
}
