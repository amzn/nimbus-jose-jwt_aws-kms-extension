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
import com.nimbusds.jose.aws.kms.crypto.impl.KmsDefaultEncryptionCryptoProvider;
import com.nimbusds.jose.aws.kms.crypto.utils.JWEHeaderUtil;
import com.nimbusds.jose.aws.kms.exceptions.TemporaryJOSEException;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.util.Base64URL;
import lombok.NonNull;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.*;

import javax.annotation.concurrent.ThreadSafe;
import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.util.Map;

/**
 * Encrypter implementation for a symmetric or asymmetric key stored in AWS KMS.
 * <p>
 * See {@link KmsDefaultEncryptionCryptoProvider} for supported algorithms and encryption methods,
 * and for details of various constructor parameters.
 */
@ThreadSafe
public class KmsDefaultEncrypter extends KmsDefaultEncryptionCryptoProvider implements JWEEncrypter {

    public KmsDefaultEncrypter(@NonNull final KmsClient kms, @NonNull final String keyId) {
        super(kms, keyId);
    }

    public KmsDefaultEncrypter(@NonNull final KmsClient kms, @NonNull final String keyId,
                               @NonNull final Map<String, String> encryptionContext) {
        super(kms, keyId, encryptionContext);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JWECryptoParts encrypt(@NonNull final JWEHeader header, @NonNull final byte[] clearText)
            throws JOSEException {

        validateJWEHeader(header);
        JWEHeader updatedHeader = JWEHeaderUtil.getJWEHeaderWithEncryptionContext(
                header, ENCRYPTION_CONTEXT_HEADER, getEncryptionContext());

        final SecretKey cek = ContentCryptoProvider.generateCEK(
                updatedHeader.getEncryptionMethod(), getJCAContext().getSecureRandom());

        final EncryptResponse encryptedKey = encryptCEK(getKeyId(), updatedHeader.getAlgorithm(), getEncryptionContext(), cek);
        final Base64URL encodedEncryptedKey = Base64URL.encode(encryptedKey.ciphertextBlob().asByteArray());

        return ContentCryptoProvider.encrypt(updatedHeader, clearText, cek, encodedEncryptedKey, getJCAContext());
    }

    private EncryptResponse encryptCEK(String keyId, JWEAlgorithm alg, Map<String, String> encryptionContext, SecretKey cek)
            throws JOSEException {
        try {
            return getKms().encrypt(EncryptRequest.builder()
                    .keyId(keyId)
                    .encryptionAlgorithm(alg.getName())
                    .plaintext(SdkBytes.fromByteBuffer(ByteBuffer.wrap(cek.getEncoded())))
                    .encryptionContext(encryptionContext)
                    .build());
        } catch (NotFoundException | DisabledException | InvalidKeyUsageException
                 | KmsInvalidStateException | InvalidGrantTokenException e) {
            throw new RemoteKeySourceException("An exception was thrown from KMS due to invalid client request.", e);
        } catch (DependencyTimeoutException | KeyUnavailableException | KmsInternalException e) {
            throw new TemporaryJOSEException("A temporary error was thrown from KMS.", e);
        }
    }
}
