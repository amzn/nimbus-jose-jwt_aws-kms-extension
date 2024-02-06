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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.refEq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.AWSKMSException;
import com.amazonaws.services.kms.model.DependencyTimeoutException;
import com.amazonaws.services.kms.model.DisabledException;
import com.amazonaws.services.kms.model.EncryptRequest;
import com.amazonaws.services.kms.model.EncryptResult;
import com.amazonaws.services.kms.model.EncryptionAlgorithmSpec;
import com.amazonaws.services.kms.model.InvalidGrantTokenException;
import com.amazonaws.services.kms.model.InvalidKeyUsageException;
import com.amazonaws.services.kms.model.KMSInternalException;
import com.amazonaws.services.kms.model.KMSInvalidStateException;
import com.amazonaws.services.kms.model.KeyUnavailableException;
import com.amazonaws.services.kms.model.NotFoundException;
import com.google.common.collect.ImmutableMap;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWECryptoParts;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.RemoteKeySourceException;
import com.nimbusds.jose.aws.kms.crypto.impl.KmsDefaultEncryptionCryptoProvider;
import com.nimbusds.jose.aws.kms.crypto.impl.KmsSymmetricCryptoProvider;
import com.nimbusds.jose.aws.kms.crypto.testUtils.EasyRandomTestUtils;
import com.nimbusds.jose.aws.kms.exceptions.TemporaryJOSEException;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.jca.JCAAware;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.jca.JWEJCAContext;
import com.nimbusds.jose.util.Base64URL;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Map;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import lombok.SneakyThrows;
import lombok.var;
import org.jeasy.random.EasyRandom;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.platform.commons.support.ReflectionSupport;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

@DisplayName("For KmsDefaultEncrypter class,")
@ExtendWith(MockitoExtension.class)
class KmsDefaultEncrypterTest {

    private EasyRandom random = EasyRandomTestUtils.getEasyRandomWithByteBufferSupport();

    @Mock
    private AWSKMS mockAwsKms;
    private final String testKeyId = random.nextObject(String.class);
    private final Map<String, String> testEncryptionContext = random.nextObject(Map.class);

    private KmsDefaultEncrypter kmsDefaultEncrypter;

    @BeforeEach
    void beforeEach() {
        kmsDefaultEncrypter = spy(new KmsDefaultEncrypter(mockAwsKms, testKeyId, testEncryptionContext));
    }

    @Nested
    @DisplayName("the encrypt method,")
    class EncryptMethod {

        private JWEHeader testJweHeader;
        private final byte[] testClearText = new byte[random.nextInt(512)];

        @BeforeEach
        @SneakyThrows
        void beforeEach() {
            random.nextBytes(testClearText);
            testJweHeader = new JWEHeader.Builder(
                    JWEAlgorithm.parse(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256.toString()),
                    EncryptionMethod.A256GCM)
                    .build();
            ReflectionSupport.invokeMethod(
                    kmsDefaultEncrypter.getClass().getSuperclass()
                            .getDeclaredMethod("validateJWEHeader", JWEHeader.class),
                    doNothing().when(kmsDefaultEncrypter),
                    testJweHeader);
        }

        @Nested
        @DisplayName("with invalid key exception from KMS,")
        class WithInvalidKMSKeyException {

            AWSKMSException parameterizedBeforeEach(final Class<AWSKMSException> invalidKeyExceptionClass) {
                final var invalidKeyException = mock(invalidKeyExceptionClass);
                when(mockAwsKms
                        .encrypt(new EncryptRequest()
                                .withKeyId(testKeyId)
                                .withEncryptionAlgorithm(testJweHeader.getAlgorithm().getName())
                                .withPlaintext(any())
                                .withEncryptionContext(testEncryptionContext)))
                        .thenThrow(invalidKeyException);

                return invalidKeyException;
            }

            @ParameterizedTest
            @DisplayName("should throw RemoteKeySourceException.")
            @ValueSource(classes = {
                    NotFoundException.class, DisabledException.class, InvalidKeyUsageException.class,
                    KMSInvalidStateException.class, InvalidGrantTokenException.class})
            void shouldThrowRemoteKeySourceException(final Class<AWSKMSException> invalidKeyExceptionClass) {
                final var invalidKeyException = parameterizedBeforeEach(invalidKeyExceptionClass);
                assertThatThrownBy(() -> kmsDefaultEncrypter.encrypt(testJweHeader, testClearText))
                        .isInstanceOf(RemoteKeySourceException.class)
                        .hasMessage("An exception was thrown from KMS due to invalid client request.")
                        .hasCause(invalidKeyException);
            }
        }

        @Nested
        @DisplayName("with a temporary exception from KMS,")
        class WithTemporaryKMSException {

            AWSKMSException parameterizedBeforeEach(final Class<AWSKMSException> temporaryKMSExceptionClass) {
                final var temporaryKMSException = mock(temporaryKMSExceptionClass);
                when(mockAwsKms
                        .encrypt(new EncryptRequest()
                                .withKeyId(testKeyId)
                                .withEncryptionAlgorithm(testJweHeader.getAlgorithm().getName())
                                .withPlaintext(any())
                                .withEncryptionContext(testEncryptionContext)))
                        .thenThrow(temporaryKMSException);

                return temporaryKMSException;
            }

            @ParameterizedTest
            @DisplayName("should throw RemoteKeySourceException.")
            @ValueSource(classes = {
                    DependencyTimeoutException.class, KeyUnavailableException.class, KMSInternalException.class})
            void shouldThrowRemoteKeySourceException(final Class<AWSKMSException> invalidKeyExceptionClass) {
                final var invalidKeyException = parameterizedBeforeEach(invalidKeyExceptionClass);
                assertThatThrownBy(() -> kmsDefaultEncrypter.encrypt(testJweHeader, testClearText))
                        .isInstanceOf(TemporaryJOSEException.class)
                        .hasMessage("A temporary error was thrown from KMS.")
                        .hasCause(invalidKeyException);
            }
        }

        @Nested
        @DisplayName("with encrypted cek from KMS,")
        class WithDataKey {

            private EncryptResult testEncryptedKey;
            private final MockedStatic<ContentCryptoProvider> mockContentCryptoProvider =
                    mockStatic(ContentCryptoProvider.class);

            @Mock
            private JWECryptoParts mockJweCryptoParts;

            @Mock
            private SecretKey mockCek;

            @Mock
            private JWEJCAContext mockJWEJCAContext;

            @Mock
            private SecureRandom mockSecureRandom;

            @BeforeEach
            void beforeEach() {
                testEncryptedKey = random.nextObject(EncryptResult.class);
                final byte[] cekBytes = new byte[10];
                random.nextBytes(cekBytes);
                when(mockCek.getEncoded()).thenReturn(cekBytes);
                when(mockAwsKms
                        .encrypt(new EncryptRequest()
                                .withKeyId(testKeyId)
                                .withEncryptionAlgorithm(testJweHeader.getAlgorithm().getName())
                                .withPlaintext(ByteBuffer.wrap(cekBytes))
                                .withEncryptionContext(testEncryptionContext)))
                        .thenReturn(testEncryptedKey);

                when(mockJWEJCAContext.getSecureRandom()).thenReturn(mockSecureRandom);
                mockContentCryptoProvider.when(
                                () -> ContentCryptoProvider.generateCEK(
                                        testJweHeader.getEncryptionMethod(),
                                        mockSecureRandom))
                        .thenReturn(mockCek);
            }

            @AfterEach
            void afterEach() {
                mockContentCryptoProvider.close();
            }

            @Nested
            @DisplayName("without encryption context,")
            class WithoutEncryptionContext {

                @BeforeEach
                @SneakyThrows
                void beforeEach() {
                    reset(kmsDefaultEncrypter);
                    kmsDefaultEncrypter = spy(new KmsDefaultEncrypter(mockAwsKms, testKeyId));
                    when(kmsDefaultEncrypter.getJCAContext()).thenReturn(mockJWEJCAContext);
                    ReflectionSupport.invokeMethod(
                            kmsDefaultEncrypter.getClass().getSuperclass()
                                    .getDeclaredMethod("validateJWEHeader", JWEHeader.class),
                            doNothing().when(kmsDefaultEncrypter),
                            testJweHeader);

                    mockContentCryptoProvider.when(
                            () -> ContentCryptoProvider.encrypt(
                                    testJweHeader,
                                    testClearText,
                                    mockCek,
                                    Base64URL.encode(testEncryptedKey.getCiphertextBlob().array()),
                                    mockJWEJCAContext))
                            .thenReturn(mockJweCryptoParts);
                }

                @Test
                @DisplayName("should encrypted JWE token.")
                @SneakyThrows
                void shouldReturnEncryptedJWEToken() {
                    final JWECryptoParts actualJweCryptoParts =
                            kmsDefaultEncrypter.encrypt(testJweHeader, testClearText);
                    assertThat(actualJweCryptoParts).isSameAs(mockJweCryptoParts);
                }
            }

            @Nested
            @DisplayName("with encryption context,")
            class WithEncryptionContext {

                @BeforeEach
                void beforeEach() {
                    when(kmsDefaultEncrypter.getJCAContext()).thenReturn(mockJWEJCAContext);
                    mockContentCryptoProvider.when(
                                    () -> ContentCryptoProvider.encrypt(
                                            refEq(new JWEHeader.Builder(testJweHeader)
                                                    .customParams(ImmutableMap.of(
                                                            KmsDefaultEncryptionCryptoProvider
                                                                    .ENCRYPTION_CONTEXT_HEADER,
                                                            testEncryptionContext))
                                                    .build()),
                                            eq(testClearText),
                                            eq(mockCek),
                                            eq(Base64URL.encode(testEncryptedKey.getCiphertextBlob().array())),
                                            eq(mockJWEJCAContext)))
                            .thenReturn(mockJweCryptoParts);
                }

                @Test
                @DisplayName("should encrypted JWE token.")
                @SneakyThrows
                void shouldReturnEncryptedJWEToken() {
                    final JWECryptoParts actualJweCryptoParts =
                            kmsDefaultEncrypter.encrypt(testJweHeader, testClearText);
                    assertThat(actualJweCryptoParts).isSameAs(mockJweCryptoParts);
                }

            }
        }

        @AfterEach
        @SneakyThrows
        void afterEach() {
            ReflectionSupport.invokeMethod(
                    kmsDefaultEncrypter.getClass().getSuperclass()
                            .getDeclaredMethod("validateJWEHeader", JWEHeader.class),
                    verify(kmsDefaultEncrypter),
                    testJweHeader);
        }
    }
}
