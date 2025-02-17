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

import com.google.common.collect.ImmutableSet;
import com.nimbusds.jose.*;
import com.nimbusds.jose.aws.kms.crypto.testUtils.EasyRandomTestUtils;
import com.nimbusds.jose.aws.kms.crypto.utils.JWEDecrypterUtil;
import com.nimbusds.jose.aws.kms.exceptions.TemporaryJOSEException;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.crypto.impl.CriticalHeaderParamsDeferral;
import com.nimbusds.jose.jca.JWEJCAContext;
import com.nimbusds.jose.util.Base64URL;
import lombok.SneakyThrows;
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
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.EncryptionAlgorithmSpec;

import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

@DisplayName("For KmsSymmetricDecrypter class, ")
@ExtendWith(MockitoExtension.class)
class KmsSymmetricDecrypterTest {

    private final EasyRandom random = EasyRandomTestUtils.getEasyRandomWithByteBufferSupport();

    @Mock
    private KmsClient mockAwsKms;
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
        private final Base64URL testEncryptedKey = random.nextObject(Base64URL.class);
        private final Base64URL testIv = random.nextObject(Base64URL.class);
        private final Base64URL testCipherText = random.nextObject(Base64URL.class);
        private final Base64URL testAuthTag = random.nextObject(Base64URL.class);

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

            @Mock
            private JWEJCAContext mockJWEJCAContext;
            @Mock
            JWEDecrypterUtil jweDecrypterUtil;
            private final DecryptResponse testDecryptResponse = DecryptResponse.builder().plaintext(SdkBytes.fromString("test", Charset.defaultCharset())).build();
            private final MockedStatic<ContentCryptoProvider> mockContentCryptoProvider =
                    mockStatic(ContentCryptoProvider.class);
            private final byte[] expectedData = new byte[random.nextInt(512)];

            @BeforeEach
            void beforeEach() {
                testJweHeader = new JWEHeader.Builder(
                        JWEAlgorithm.parse(EncryptionAlgorithmSpec.SYMMETRIC_DEFAULT.toString()),
                        EncryptionMethod.A256GCM)
                        .criticalParams(testDeferredCriticalHeaders)
                        .build();
                random.nextBytes(expectedData);
                mockContentCryptoProvider.when(
                                () -> ContentCryptoProvider.decrypt(
                                        testJweHeader, testEncryptedKey, testIv, testCipherText, testAuthTag,
                                        new SecretKeySpec(
                                                testDecryptResponse.plaintext().asByteArray(),
                                                testJweHeader.getAlgorithm().toString()),
                                        kmsSymmetricDecrypter.getJCAContext()))
                        .thenReturn(expectedData);
                when(kmsSymmetricDecrypter.getJCAContext()).thenReturn(mockJWEJCAContext);
            }

            @Nested
            @DisplayName("with exception thrown from JWEDecrypterUtil,")
            class WithExceptionThrownFromJWEDecrypterUtil {

                @ParameterizedTest
                @SneakyThrows
                @DisplayName("should throw exception,")
                @ValueSource(classes = {
                        JOSEException.class, RemoteKeySourceException.class, TemporaryJOSEException.class
                })
                void shouldThrowException(final Class<Throwable> exceptionClass) {
                    try (MockedStatic<JWEDecrypterUtil> utilMockedStatic = mockStatic(JWEDecrypterUtil.class)) {
                        utilMockedStatic.when(() -> JWEDecrypterUtil.decrypt(mockAwsKms, testKeyId, testEncryptionContext,
                                        testJweHeader, testEncryptedKey, testIv, testCipherText,
                                        testAuthTag, mockJWEJCAContext))
                                .thenThrow(exceptionClass);
                        assertThrows(exceptionClass, () -> kmsSymmetricDecrypter.decrypt(
                                testJweHeader, testEncryptedKey, testIv, testCipherText, testAuthTag));
                    }
                }
            }

            @Nested
            @DisplayName("with decryption result from JWEDecrypterUtil,")
            class WithDecryptionResultFromJWEDecrypterUtil {

                @BeforeEach
                @SneakyThrows
                void beforeEach() {
                    when(mockAwsKms
                            .decrypt(DecryptRequest.builder()
                                    .encryptionContext(testEncryptionContext)
                                    .encryptionAlgorithm(testJweHeader.getAlgorithm().getName())
                                    .keyId(testKeyId)
                                    .ciphertextBlob(SdkBytes.fromByteBuffer(ByteBuffer.wrap(testEncryptedKey.decode())))
                                    .build()))
                            .thenReturn(testDecryptResponse);
                    when(JWEDecrypterUtil.decrypt(mockAwsKms, testKeyId, testEncryptionContext,
                            testJweHeader, testEncryptedKey, testIv, testCipherText,
                            testAuthTag, mockJWEJCAContext))
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
            }

            @AfterEach
            @SneakyThrows
            void afterEach() {
                mockContentCryptoProvider.close();
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
