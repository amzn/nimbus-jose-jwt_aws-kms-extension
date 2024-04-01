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
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.AWSKMSException;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.DecryptResult;
import com.amazonaws.services.kms.model.DependencyTimeoutException;
import com.amazonaws.services.kms.model.DisabledException;
import com.amazonaws.services.kms.model.EncryptionAlgorithmSpec;
import com.amazonaws.services.kms.model.InvalidGrantTokenException;
import com.amazonaws.services.kms.model.InvalidKeyUsageException;
import com.amazonaws.services.kms.model.KMSInternalException;
import com.amazonaws.services.kms.model.KMSInvalidStateException;
import com.amazonaws.services.kms.model.KeyUnavailableException;
import com.amazonaws.services.kms.model.NotFoundException;
import com.google.common.collect.ImmutableSet;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.RemoteKeySourceException;
import com.nimbusds.jose.aws.kms.crypto.testUtils.EasyRandomTestUtils;
import com.nimbusds.jose.aws.kms.exceptions.TemporaryJOSEException;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.crypto.impl.CriticalHeaderParamsDeferral;
import com.nimbusds.jose.util.Base64URL;
import java.nio.ByteBuffer;
import java.util.Map;
import java.util.Set;
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

@DisplayName("For KmsSymmetricDecrypter class, ")
@ExtendWith(MockitoExtension.class)
class KmsSymmetricDecrypterTest {

    private final EasyRandom random = EasyRandomTestUtils.getEasyRandomWithByteBufferSupport();

    @Mock
    private AWSKMS mockAwsKms;
    private String testKeyId;
    private Map<String, String> testEncryptionContext;
    private Set<String> testDeferredCriticalHeaders;

    private KmsSymmetricDecrypter kmsSymmetricDecrypter;

    @BeforeEach
    void setUp() {
        testKeyId = random.nextObject(String.class);
        testEncryptionContext = random.nextObject(Map.class);
        testDeferredCriticalHeaders = ImmutableSet.of("test-deferred-critical-header");
    }

    @Nested
    @DisplayName("the getProcessedCriticalHeaderParams method,")
    class GetProcessedCriticalHeaderParams {

        @BeforeEach
        void beforeEach() {
            kmsSymmetricDecrypter = new KmsSymmetricDecrypter(mockAwsKms, testKeyId);
        }

        @Test
        @DisplayName("should return processed critical headers.")
        void shouldReturnProcessedCriticalHeaders() {
            final Set<String> actualProcessedCriticalHeader = kmsSymmetricDecrypter.getProcessedCriticalHeaderParams();
            assertThat(actualProcessedCriticalHeader)
                    .isEqualTo(new CriticalHeaderParamsDeferral().getProcessedCriticalHeaderParams());
        }
    }

    @Nested
    @DisplayName("the getDeferredCriticalHeaderParams method,")
    class GetDeferredCriticalHeaderParams {

        @BeforeEach
        void beforeEach() {
            kmsSymmetricDecrypter = new KmsSymmetricDecrypter(mockAwsKms, testKeyId, testDeferredCriticalHeaders);
        }

        @Test
        @DisplayName("should return deferred critical headers.")
        void shouldReturnDeferredCriticalHeaders() {
            final Set<String> actualDeferredCriticalHeader = kmsSymmetricDecrypter.getDeferredCriticalHeaderParams();
            assertThat(actualDeferredCriticalHeader).isEqualTo(testDeferredCriticalHeaders);
        }
    }

    @Nested
    @DisplayName("the decrypt method,")
    class DecryptMethod {

        private JWEHeader testJweHeader;
        private Base64URL testEncryptedKey = random.nextObject(Base64URL.class);
        private Base64URL testIv = random.nextObject(Base64URL.class);
        private Base64URL testCipherText = random.nextObject(Base64URL.class);
        private Base64URL testAuthTag = random.nextObject(Base64URL.class);

        @BeforeEach
        @SneakyThrows
        void beforeEach() {
            kmsSymmetricDecrypter = spy(new KmsSymmetricDecrypter(mockAwsKms, testKeyId, testEncryptionContext,
                    testDeferredCriticalHeaders));
        }

        @Nested
        @DisplayName("with missing critical header,")
        class WithMissingCriticalHeader {

            @BeforeEach
            @SneakyThrows
            void beforeEach() {
                testJweHeader = new JWEHeader.Builder(
                        JWEAlgorithm.parse(EncryptionAlgorithmSpec.SYMMETRIC_DEFAULT.toString()),
                        EncryptionMethod.A256GCM)
                        .criticalParams(ImmutableSet.of("test-critical-header"))
                        .build();
                ReflectionSupport.invokeMethod(
                        kmsSymmetricDecrypter.getClass().getSuperclass()
                                .getDeclaredMethod("validateJWEHeader", JWEHeader.class),
                        doNothing().when(kmsSymmetricDecrypter),
                        testJweHeader);
            }

            @Test
            @DisplayName("should throw JOSEException.")
            void shouldThrowJOSEException() {
                assertThatThrownBy(
                        () -> kmsSymmetricDecrypter.decrypt(testJweHeader, testEncryptedKey, testIv, testCipherText,
                                testAuthTag))
                        .isInstanceOf(JOSEException.class)
                        .hasNoCause();
            }
        }

        @Nested
        @DisplayName("with critical header,")
        class WithCriticalHeader {

            @BeforeEach
            @SneakyThrows
            void beforeEach() {
                testJweHeader = new JWEHeader.Builder(
                        JWEAlgorithm.parse(EncryptionAlgorithmSpec.SYMMETRIC_DEFAULT.toString()),
                        EncryptionMethod.A256GCM)
                        .criticalParams(testDeferredCriticalHeaders)
                        .build();
                ReflectionSupport.invokeMethod(
                        kmsSymmetricDecrypter.getClass().getSuperclass()
                                .getDeclaredMethod("validateJWEHeader", JWEHeader.class),
                        doNothing().when(kmsSymmetricDecrypter),
                        testJweHeader);
            }

            @Nested
            @DisplayName("with invalid key exception from KMS,")
            class WithInvalidKMSKeyException {

                AWSKMSException parameterizedBeforeEach(final Class<AWSKMSException> invalidKeyExceptionClass) {
                    final var invalidKeyException = mock(invalidKeyExceptionClass);
                    when(mockAwsKms
                            .decrypt(new DecryptRequest()
                                    .withEncryptionContext(testEncryptionContext)
                                    .withKeyId(testKeyId)
                                    .withCiphertextBlob(ByteBuffer.wrap(testEncryptedKey.decode()))))
                            .thenThrow(invalidKeyException);

                    return invalidKeyException;
                }

                @ParameterizedTest
                @DisplayName("should throw RemoteKeySourceException.")
                @ValueSource(classes = {
                        NotFoundException.class, DisabledException.class, InvalidKeyUsageException.class,
                        KeyUnavailableException.class, KMSInvalidStateException.class})
                void shouldThrowRemoteKeySourceException(final Class<AWSKMSException> invalidKeyExceptionClass) {
                    final var invalidKeyException = parameterizedBeforeEach(invalidKeyExceptionClass);
                    assertThatThrownBy(
                            () -> kmsSymmetricDecrypter.decrypt(testJweHeader, testEncryptedKey, testIv, testCipherText,
                                    testAuthTag))
                            .isInstanceOf(RemoteKeySourceException.class)
                            .hasMessage("An exception was thrown from KMS due to invalid key.")
                            .hasCause(invalidKeyException);
                }
            }

            @Nested
            @DisplayName("with a temporary exception from KMS,")
            class WithTemporaryKMSException {

                AWSKMSException parameterizedBeforeEach(final Class<AWSKMSException> temporaryKMSExceptionClass) {
                    final var temporaryKMSException = mock(temporaryKMSExceptionClass);
                    when(mockAwsKms
                            .decrypt(new DecryptRequest()
                                    .withEncryptionContext(testEncryptionContext)
                                    .withKeyId(testKeyId)
                                    .withCiphertextBlob(ByteBuffer.wrap(testEncryptedKey.decode()))))
                            .thenThrow(temporaryKMSException);

                    return temporaryKMSException;
                }

                @ParameterizedTest
                @DisplayName("should throw RemoteKeySourceException.")
                @ValueSource(classes = {
                        DependencyTimeoutException.class, InvalidGrantTokenException.class,
                        KMSInternalException.class})
                void shouldThrowRemoteKeySourceException(final Class<AWSKMSException> invalidKeyExceptionClass) {
                    final var invalidKeyException = parameterizedBeforeEach(invalidKeyExceptionClass);
                    assertThatThrownBy(
                            () -> kmsSymmetricDecrypter.decrypt(testJweHeader, testEncryptedKey, testIv, testCipherText,
                                    testAuthTag))
                            .isInstanceOf(TemporaryJOSEException.class)
                            .hasMessage("A temporary error was thrown from KMS.")
                            .hasCause(invalidKeyException);
                }
            }

            @Nested
            @DisplayName("with a decryption result from KMS,")
            class WithDecyptionResultFromKMS {

                private final DecryptResult testDecryptResult = random.nextObject(DecryptResult.class);
                private final MockedStatic<ContentCryptoProvider> mockContentCryptoProvider =
                        mockStatic(ContentCryptoProvider.class);
                private byte[] expectedData = new byte[random.nextInt(512)];

                @BeforeEach
                void beforeEach() {
                    when(mockAwsKms
                            .decrypt(new DecryptRequest()
                                    .withEncryptionContext(testEncryptionContext)
                                    .withKeyId(testKeyId)
                                    .withCiphertextBlob(ByteBuffer.wrap(testEncryptedKey.decode()))))
                            .thenReturn(testDecryptResult);

                    random.nextBytes(expectedData);
                    mockContentCryptoProvider.when(
                                    () -> ContentCryptoProvider.decrypt(
                                            testJweHeader, testEncryptedKey, testIv, testCipherText, testAuthTag,
                                            new SecretKeySpec(
                                                    testDecryptResult.getPlaintext().array(),
                                                    testJweHeader.getAlgorithm().toString()),
                                            kmsSymmetricDecrypter.getJCAContext()))
                            .thenReturn(expectedData);
                }

                @Test
                @DisplayName("should return decrypted data.")
                @SneakyThrows
                void shouldReturnDecryptedData() {
                    final byte[] actualData = kmsSymmetricDecrypter.decrypt(
                            testJweHeader, testEncryptedKey, testIv, testCipherText, testAuthTag);
                    assertThat(actualData).isEqualTo(expectedData);
                }

                @AfterEach
                @SneakyThrows
                void afterEach() {
                    mockContentCryptoProvider.close();
                }
            }
        }

        @AfterEach
        @SneakyThrows
        void afterEach() {
            ReflectionSupport.invokeMethod(
                    kmsSymmetricDecrypter.getClass().getSuperclass()
                            .getDeclaredMethod("validateJWEHeader", JWEHeader.class),
                    verify(kmsSymmetricDecrypter),
                    testJweHeader);
        }
    }
}