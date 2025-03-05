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

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.DependencyTimeoutException;
import com.amazonaws.services.kms.model.DisabledException;
import com.amazonaws.services.kms.model.EncryptRequest;
import com.amazonaws.services.kms.model.EncryptResult;
import com.amazonaws.services.kms.model.InvalidGrantTokenException;
import com.amazonaws.services.kms.model.InvalidKeyUsageException;
import com.amazonaws.services.kms.model.KMSInternalException;
import com.amazonaws.services.kms.model.KMSInvalidStateException;
import com.amazonaws.services.kms.model.KeyUnavailableException;
import com.amazonaws.services.kms.model.NotFoundException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWECryptoParts;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.RemoteKeySourceException;
import com.nimbusds.jose.aws.kms.crypto.impl.KmsDefaultEncryptionCryptoProvider;
import com.nimbusds.jose.aws.kms.crypto.utils.JWEHeaderUtil;
import com.nimbusds.jose.aws.kms.exceptions.TemporaryJOSEException;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.util.Base64URL;
import java.nio.ByteBuffer;
import java.util.Map;
import javax.annotation.concurrent.ThreadSafe;
import javax.crypto.SecretKey;
import lombok.NonNull;

/**
 * Encrypter implementation for a symmetric or asymmetric key stored in AWS KMS.
 * <p>
 * See {@link KmsDefaultEncryptionCryptoProvider} for supported algorithms and encryption methods,
 * and for details of various constructor parameters.
 */
@ThreadSafe
public class KmsDefaultEncrypter extends KmsDefaultEncryptionCryptoProvider implements JWEEncrypter {

    public KmsDefaultEncrypter(@NonNull final AWSKMS kms, @NonNull final String keyId) {
        super(kms, keyId);
    }

    public KmsDefaultEncrypter(@NonNull final AWSKMS kms, @NonNull final String keyId,
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

        final EncryptResult encryptedKey = encryptCEK(getKeyId(), updatedHeader.getAlgorithm(), getEncryptionContext(), cek);
        final Base64URL encodedEncryptedKey = Base64URL.encode(encryptedKey.getCiphertextBlob().array());

        return ContentCryptoProvider.encrypt(updatedHeader, clearText, cek, encodedEncryptedKey, getJCAContext());
    }

    private EncryptResult encryptCEK(String keyId, JWEAlgorithm alg, Map<String, String> encryptionContext, SecretKey cek)
            throws JOSEException {
        try {
            return getKms().encrypt(new EncryptRequest()
                    .withKeyId(keyId)
                    .withEncryptionAlgorithm(JWE_TO_KMS_ALGORITHM_SPEC.get(alg))
                    .withPlaintext(ByteBuffer.wrap(cek.getEncoded()))
                    .withEncryptionContext(encryptionContext));
        } catch (NotFoundException | DisabledException | InvalidKeyUsageException
                 | KMSInvalidStateException | InvalidGrantTokenException e) {
            throw new RemoteKeySourceException("An exception was thrown from KMS due to invalid client request.", e);
        } catch (DependencyTimeoutException | KeyUnavailableException | KMSInternalException e) {
            throw new TemporaryJOSEException("A temporary error was thrown from KMS.", e);
        }
    }
}
