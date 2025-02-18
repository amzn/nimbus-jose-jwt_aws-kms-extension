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
import com.nimbusds.jose.aws.kms.crypto.impl.KmsSymmetricCryptoProvider;
import com.nimbusds.jose.aws.kms.crypto.utils.JWEHeaderUtil;
import com.nimbusds.jose.aws.kms.exceptions.TemporaryJOSEException;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.util.Base64URL;
import lombok.NonNull;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.*;

import javax.annotation.concurrent.ThreadSafe;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Map;

/**
 * Encrypter implementation for SYMMETRIC (AES based) signing with public/private key stored in AWS KMS.
 * <p>
 * See {@link KmsSymmetricCryptoProvider} for supported algorithms and encryption methods, and for details of various
 * constructor parameters.
 */
@ThreadSafe
public class KmsSymmetricEncrypter extends KmsSymmetricCryptoProvider implements JWEEncrypter {

    public KmsSymmetricEncrypter(@NonNull final KmsClient kms, @NonNull final String keyId) {
        super(kms, keyId);
    }

    public KmsSymmetricEncrypter(@NonNull final KmsClient kms, @NonNull final String keyId,
                                 @NonNull final Map<String, String> encryptionContext) {
        super(kms, keyId, encryptionContext);
    }

    @Override
    public JWECryptoParts encrypt(@NonNull final JWEHeader header, @NonNull final byte[] clearText)
            throws JOSEException {

        validateJWEHeader(header);

        final JWEHeader updatedHeader; // We need to work on the header
        final Base64URL encryptedKey; // The second JWE part

        // Generate and encrypt the CEK according to the enc method
        GenerateDataKeyResponse generateDataKeyResponse = generateDataKey(getKeyId(), header.getEncryptionMethod());
        final SecretKey cek = new SecretKeySpec(
                generateDataKeyResponse.plaintext().asByteArray(), header.getAlgorithm().toString());

        encryptedKey = Base64URL.encode(generateDataKeyResponse.ciphertextBlob().asByteArray());
        updatedHeader = JWEHeaderUtil.getJWEHeaderWithEncryptionContext(
                header, ENCRYPTION_CONTEXT_HEADER, getEncryptionContext());

        return ContentCryptoProvider.encrypt(updatedHeader, clearText, cek, encryptedKey, getJCAContext());
    }

    private GenerateDataKeyResponse generateDataKey(String keyId, EncryptionMethod encryptionMethod)
            throws JOSEException {
        try {
            return getKms().generateDataKey(GenerateDataKeyRequest.builder()
                    .keyId(keyId)
                    .keySpec(ENCRYPTION_METHOD_TO_DATA_KEY_SPEC_MAP.get(encryptionMethod))
                    .encryptionContext(getEncryptionContext())
                    .build());
        } catch (NotFoundException | DisabledException | InvalidKeyUsageException | KeyUnavailableException
                 | KmsInvalidStateException e) {
            throw new RemoteKeySourceException("An exception was thrown from KMS due to invalid key.", e);
        } catch (DependencyTimeoutException | InvalidGrantTokenException | KmsInternalException e) {
            throw new TemporaryJOSEException("A temporary error was thrown from KMS.", e);
        }
    }
}
