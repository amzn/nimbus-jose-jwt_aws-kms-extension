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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.MessageType;
import com.amazonaws.services.kms.model.SigningAlgorithmSpec;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import lombok.SneakyThrows;
import org.jeasy.random.EasyRandom;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

@DisplayName("For KmsAsymmetricSigningCryptoProvider class,")
@ExtendWith(MockitoExtension.class)
public class KmsAsymmetricSigningCryptoProviderTest {

    private EasyRandom random;

    @Mock
    private AWSKMS mockAwsKms;
    private String testPrivateKeyId;
    private MessageType testMessageType;

    private KmsAsymmetricSigningCryptoProvider kmsAsymmetricSigningCryptoProvider;

    @BeforeEach
    void beforeEach() {
        random = new EasyRandom();

        testPrivateKeyId = random.nextObject(String.class);
        testMessageType = random.nextObject(MessageType.class);

        kmsAsymmetricSigningCryptoProvider = mock(KmsAsymmetricSigningCryptoProvider.class, withSettings()
                .useConstructor(mockAwsKms, testPrivateKeyId, testMessageType)
                .defaultAnswer(CALLS_REAL_METHODS));
    }

    @Nested
    @DisplayName("the getMessage method,")
    class GetMessage {

        private JWSHeader testJwsHeader;
        private byte[] testSigningInputBytes;

        @BeforeEach
        void beforeEach() {
            testSigningInputBytes = new byte[random.nextInt(100)];
            random.nextBytes(testSigningInputBytes);
        }

        @Nested
        @DisplayName("with invalid JWS algorithm in header,")
        class WithInvalidJwsAlgorithmInHeader {

            @BeforeEach
            void beforeEach() {
                testJwsHeader = new JWSHeader.Builder(JWSAlgorithm.parse("Invalid Algo")).build();
            }

            @Test
            @DisplayName("should throw JOSEException.")
            void shouldThrowException() {
                assertThatThrownBy(() -> kmsAsymmetricSigningCryptoProvider.getMessage(testJwsHeader, testSigningInputBytes))
                        .isInstanceOf(JOSEException.class)
                        .hasMessage(String.format("No digest algorithm exist for the JWS algorithm %s in map: %s",
                                testJwsHeader.getAlgorithm(),
                                KmsAsymmetricSigningCryptoProvider.JWS_ALGORITHM_TO_MESSAGE_DIGEST_ALGORITHM));
            }
        }

        @Nested
        @DisplayName("with valid JWS algorithm in header,")
        class WithValidJwsAlgorithmInHeader {

            private ByteBuffer expectedMessage;

            @BeforeEach
            void beforeEach() {
                testJwsHeader = new JWSHeader.Builder(JWSAlgorithm.PS512).build();
                testSigningInputBytes = "Test Payload / ٹیسٹ پیلوڈ".getBytes(StandardCharsets.UTF_8);
                expectedMessage = ByteBuffer.wrap(testSigningInputBytes);
            }

            @Nested
            @DisplayName("with raw message,")
            class WithRawMessage {

                @BeforeEach
                void beforeEach() {
                    testMessageType = MessageType.RAW;
                    kmsAsymmetricSigningCryptoProvider = mock(KmsAsymmetricSigningCryptoProvider.class, withSettings()
                            .useConstructor(mockAwsKms, testPrivateKeyId, testMessageType)
                            .defaultAnswer(CALLS_REAL_METHODS));
                }

                @Test
                @DisplayName("should return message ByteBuffer.")
                @SneakyThrows
                void shouldReturnMessageByteBuffer() {
                    ByteBuffer actualMessage = kmsAsymmetricSigningCryptoProvider.getMessage(testJwsHeader, testSigningInputBytes);
                    assertThat(actualMessage).isEqualTo(expectedMessage);
                }
            }

            @Nested
            @DisplayName("with digest message,")
            class WithDigestMessage {

                private final MockedStatic<MessageDigest> mockMessageDigest = mockStatic(MessageDigest.class);

                @BeforeEach
                void beforeEach() {
                    testMessageType = MessageType.DIGEST;
                    kmsAsymmetricSigningCryptoProvider = mock(KmsAsymmetricSigningCryptoProvider.class, withSettings()
                            .useConstructor(mockAwsKms, testPrivateKeyId, testMessageType)
                            .defaultAnswer(CALLS_REAL_METHODS));
                }

                @Nested
                @DisplayName("with invalid message digest algorithm,")
                class WithInvalidDigestAlgorithm {

                    @Mock
                    private NoSuchAlgorithmException mockNoSuchAlgorithmException;

                    @BeforeEach
                    @SneakyThrows
                    void beforeEach() {
                        mockMessageDigest
                                .when(() -> MessageDigest.getInstance(
                                        KmsAsymmetricSigningCryptoProvider.JWS_ALGORITHM_TO_MESSAGE_DIGEST_ALGORITHM.get(
                                                testJwsHeader.getAlgorithm())))
                                .thenThrow(mockNoSuchAlgorithmException);
                    }

                    @Test
                    @DisplayName("should throw JOSEException.")
                    void shouldThrowException() {
                        assertThatThrownBy(
                                () -> kmsAsymmetricSigningCryptoProvider.getMessage(testJwsHeader, testSigningInputBytes))
                                .isInstanceOf(JOSEException.class)
                                .hasMessage("Invalid message digest algorithm.")
                                .hasCause(mockNoSuchAlgorithmException);
                    }
                }

                @Nested
                @DisplayName("with valid message digest algorithm,")
                class WithValidDigestAlgorithm {

                    @Mock
                    private MessageDigest mockMessageDigestProvider;

                    private ByteBuffer expectedDigestMessage;

                    @BeforeEach
                    @SneakyThrows
                    void beforeEach() {
                        mockMessageDigest
                                .when(() -> MessageDigest.getInstance(
                                        KmsAsymmetricSigningCryptoProvider.JWS_ALGORITHM_TO_MESSAGE_DIGEST_ALGORITHM.get(
                                                testJwsHeader.getAlgorithm())))
                                .thenReturn(mockMessageDigestProvider);

                        expectedDigestMessage = ByteBuffer.allocate(random.nextInt(512));
                        random.nextBytes(expectedDigestMessage.array());
                        when(mockMessageDigestProvider.digest(expectedMessage.array()))
                                .thenReturn(expectedDigestMessage.array());
                    }

                    @Test
                    @DisplayName("should return message ByteBuffer.")
                    @SneakyThrows
                    void shouldReturnMessageByteBuffer() {
                        ByteBuffer actualMessage = kmsAsymmetricSigningCryptoProvider.getMessage(testJwsHeader,
                                testSigningInputBytes);
                        assertThat(actualMessage).isEqualTo(expectedDigestMessage);
                    }
                }

                @AfterEach
                void afterEach() {
                    mockMessageDigest.close();
                }
            }
        }
    }
}
