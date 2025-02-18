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

import com.google.common.collect.ImmutableMap;
import com.nimbusds.jose.*;
import com.nimbusds.jose.aws.kms.crypto.impl.KmsDefaultEncryptionCryptoProvider;
import com.nimbusds.jose.aws.kms.crypto.testUtils.EasyRandomTestUtils;
import com.nimbusds.jose.aws.kms.exceptions.TemporaryJOSEException;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.jca.JWEJCAContext;
import com.nimbusds.jose.util.Base64URL;
import lombok.SneakyThrows;
import lombok.var;
import org.jeasy.random.EasyRandom;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.platform.commons.support.ReflectionSupport;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.*;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@DisplayName("For KmsDefaultEncrypter class,")
@ExtendWith(MockitoExtension.class)
class KmsDefaultEncrypterTest {

    private final EasyRandom random = EasyRandomTestUtils.getEasyRandomWithByteBufferSupport();

    @Mock
    private KmsClient mockAwsKms;
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

            KmsException parameterizedBeforeEach(final Class<KmsException> invalidKeyExceptionClass) {
                final var invalidKeyException = mock(invalidKeyExceptionClass);
                when(mockAwsKms
                        .encrypt(EncryptRequest.builder()
                                .keyId(testKeyId)
                                .encryptionAlgorithm(testJweHeader.getAlgorithm().getName())
                                .plaintext(any())
                                .encryptionContext(testEncryptionContext)
                                .build()))
                        .thenThrow(invalidKeyException);

                return invalidKeyException;
            }

            @ParameterizedTest
            @DisplayName("should throw RemoteKeySourceException.")
            @ValueSource(classes = {
                    NotFoundException.class, DisabledException.class, InvalidKeyUsageException.class,
                    KmsInvalidStateException.class, InvalidGrantTokenException.class})
            void shouldThrowRemoteKeySourceException(final Class<KmsException> invalidKeyExceptionClass) {
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

            KmsException parameterizedBeforeEach(final Class<KmsException> temporaryKMSExceptionClass) {
                final var temporaryKMSException = mock(temporaryKMSExceptionClass);
                when(mockAwsKms
                        .encrypt(EncryptRequest.builder()
                                .keyId(testKeyId)
                                .encryptionAlgorithm(testJweHeader.getAlgorithm().getName())
                                .plaintext(any())
                                .encryptionContext(testEncryptionContext)
                                .build()))
                        .thenThrow(temporaryKMSException);

                return temporaryKMSException;
            }

            @ParameterizedTest
            @DisplayName("should throw RemoteKeySourceException.")
            @ValueSource(classes = {
                    DependencyTimeoutException.class, KeyUnavailableException.class, KmsInternalException.class})
            void shouldThrowRemoteKeySourceException(final Class<KmsException> invalidKeyExceptionClass) {
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

            private EncryptResponse testEncryptedKey;
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
                testEncryptedKey = EncryptResponse.builder().ciphertextBlob(SdkBytes.fromString("test", Charset.defaultCharset())).build();
                final byte[] cekBytes = new byte[10];
                random.nextBytes(cekBytes);
                when(mockCek.getEncoded()).thenReturn(cekBytes);
                when(mockAwsKms
                        .encrypt(EncryptRequest.builder()
                                .keyId(testKeyId)
                                .encryptionAlgorithm(testJweHeader.getAlgorithm().getName())
                                .plaintext(SdkBytes.fromByteBuffer(ByteBuffer.wrap(cekBytes)))
                                .encryptionContext(testEncryptionContext)
                                .build()))
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
                                            Base64URL.encode(testEncryptedKey.ciphertextBlob().asByteArray()),
                                            mockJWEJCAContext))
                            .thenReturn(mockJweCryptoParts);

                    reset(mockAwsKms);
                    final byte[] cekBytes = new byte[10];
                    random.nextBytes(cekBytes);
                    when(mockCek.getEncoded()).thenReturn(cekBytes);
                    when(mockAwsKms
                            .encrypt(EncryptRequest.builder()
                                    .keyId(testKeyId)
                                    .encryptionAlgorithm(testJweHeader.getAlgorithm().getName())
                                    .plaintext(SdkBytes.fromByteBuffer(ByteBuffer.wrap(cekBytes)))
                                    .build()))
                            .thenReturn(testEncryptedKey);
                }

                @Test
                @DisplayName("should encrypt JWE token.")
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
                                            eq(Base64URL.encode(testEncryptedKey.ciphertextBlob().asByteArray())),
                                            eq(mockJWEJCAContext)))
                            .thenReturn(mockJweCryptoParts);
                }

                @Test
                @DisplayName("should encrypt JWE token.")
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
