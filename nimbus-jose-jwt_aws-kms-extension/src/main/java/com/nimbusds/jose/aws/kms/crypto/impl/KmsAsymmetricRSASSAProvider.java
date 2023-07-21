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
 *
 * @deprecated use {@link KmsAsymmetricSigningCryptoProvider} instead.
 */
@Deprecated
public abstract class KmsAsymmetricRSASSAProvider extends KmsAsymmetricSigningCryptoProvider {
    protected KmsAsymmetricRSASSAProvider(
            @NonNull final AWSKMS kms, @NonNull final String privateKeyId, @NonNull final MessageType messageType) {
        super(kms, privateKeyId, messageType);
    }
}
