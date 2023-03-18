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
import com.amazonaws.services.kms.model.*;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.RemoteKeySourceException;
import com.nimbusds.jose.aws.kms.exceptions.TemporaryJOSEException;
import com.nimbusds.jose.util.Base64URL;
import lombok.SneakyThrows;
import lombok.var;
import org.jeasy.random.EasyRandom;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.platform.commons.support.ReflectionSupport;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@DisplayName("For KmsAsymmetricECDSASigner class,")
@ExtendWith(MockitoExtension.class)
public class KmsAsymmetricEcdsaSignerTest {

    private final EasyRandom random = new EasyRandom();

    @Mock
    private AWSKMS mockAwsKms;
    private String testPrivateKeyId;
    private MessageType testMessageType;

    private KmsAsymmetricECDSASigner kmsAsymmetricEcdsaSigner;

    @BeforeEach
    void setUp() {
        testPrivateKeyId = random.nextObject(String.class);
        testMessageType = random.nextObject(MessageType.class);

        kmsAsymmetricEcdsaSigner = spy(new KmsAsymmetricECDSASigner(mockAwsKms, testPrivateKeyId, testMessageType));
    }

    @Nested
    @DisplayName("the sign method,")
    class SignMethod {

        private JWSHeader testJweHeader;
        private byte[] testSigningInput;

        @Mock
        private ByteBuffer mockMessage;

        @BeforeEach
        @SneakyThrows
        void beforeEach() {
            testJweHeader = new JWSHeader.Builder(random.nextObject(JWSAlgorithm.class)).build();

            testSigningInput = new byte[random.nextInt(512)];
            random.nextBytes(testSigningInput);

            mockMessage = ByteBuffer.allocate(random.nextInt(512));
            random.nextBytes(mockMessage.array());

            ReflectionSupport.invokeMethod(
                    kmsAsymmetricEcdsaSigner.getClass().getSuperclass()
                            .getDeclaredMethod("getMessage", JWSHeader.class, byte[].class),
                    doReturn(mockMessage).when(kmsAsymmetricEcdsaSigner),
                    testJweHeader,
                    testSigningInput);
        }

        @Nested
        @DisplayName("with invalid signing key,")
        class WithInvalidSigningKey {

            @SneakyThrows
            AWSKMSException parameterizedBeforeEach(Class<AWSKMSException> invalidSigningExceptionClass) {
                final var mockInvalidSigningException = mock(invalidSigningExceptionClass);
                when(mockAwsKms
                        .sign(new SignRequest()
                                .withKeyId(testPrivateKeyId)
                                .withMessageType(testMessageType)
                                .withMessage(mockMessage)
                                .withSigningAlgorithm(testJweHeader.getAlgorithm().toString())))
                        .thenThrow(mockInvalidSigningException);
                return mockInvalidSigningException;
            }

            @ParameterizedTest
            @DisplayName("should throw RemoteKeySourceException.")
            @ValueSource(classes = {
                    NotFoundException.class, DisabledException.class, KeyUnavailableException.class,
                    InvalidKeyUsageException.class, KMSInvalidStateException.class})
            void shouldThrowRemoteKeySourceException(Class<AWSKMSException> exceptionClass) {
                final var mockInvalidSigningException = parameterizedBeforeEach(exceptionClass);
                assertThatThrownBy(() -> kmsAsymmetricEcdsaSigner.sign(testJweHeader, testSigningInput))
                        .isInstanceOf(RemoteKeySourceException.class)
                        .hasMessage("An exception was thrown from KMS due to invalid key.")
                        .hasCause(mockInvalidSigningException);
            }
        }

        @Nested
        @DisplayName("with temporary exception from KMS,")
        class WithTemporaryExceptionFromKms {

            @SneakyThrows
            AWSKMSException parameterizedBeforeEach(Class<AWSKMSException> temporaryKmsExceptionClass) {
                final var mockTemporaryKmsException = mock(temporaryKmsExceptionClass);
                when(mockAwsKms
                        .sign(new SignRequest()
                                .withKeyId(testPrivateKeyId)
                                .withMessageType(testMessageType)
                                .withMessage(mockMessage)
                                .withSigningAlgorithm(testJweHeader.getAlgorithm().toString())))
                        .thenThrow(mockTemporaryKmsException);
                return mockTemporaryKmsException;
            }

            @ParameterizedTest
            @DisplayName("should throw TemporaryJOSEException.")
            @ValueSource(classes = {
                    DependencyTimeoutException.class, InvalidGrantTokenException.class, KMSInternalException.class})
            void shouldThrowJOSEException(Class<AWSKMSException> exceptionClass) {
                final var mockInvalidSigningException = parameterizedBeforeEach(exceptionClass);
                assertThatThrownBy(() -> kmsAsymmetricEcdsaSigner.sign(testJweHeader, testSigningInput))
                        .isInstanceOf(TemporaryJOSEException.class)
                        .hasMessage("A temporary exception was thrown from KMS.")
                        .hasCause(mockInvalidSigningException);
            }
        }

        @Nested
        @DisplayName("with sign result from KMS,")
        class WithSignResultFromKms {

            @Mock
            private SignResult mockSignResult;

            private Base64URL expectedSignature;

            @BeforeEach
            void beforeEach() {
                when(mockAwsKms
                        .sign(new SignRequest()
                                .withKeyId(testPrivateKeyId)
                                .withMessageType(testMessageType)
                                .withMessage(mockMessage)
                                .withSigningAlgorithm(testJweHeader.getAlgorithm().toString())))
                        .thenReturn(mockSignResult);

                final var testSignatureByteBuffer = ByteBuffer.allocate(random.nextInt(512));
                random.nextBytes(testSignatureByteBuffer.array());
                when(mockSignResult.getSignature()).thenReturn(testSignatureByteBuffer);
                expectedSignature = Base64URL.encode(testSignatureByteBuffer.array());
            }

            @Test
            @DisplayName("should return based-64-URL encoded signature.")
            @SneakyThrows
            void shouldReturnValidResponse() {
                final var actualSignature = kmsAsymmetricEcdsaSigner.sign(testJweHeader, testSigningInput);
                assertThat(actualSignature).isEqualTo(expectedSignature);
            }
        }
    }
}