package com.nimbusds.jose.aws.kms.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.AWSKMSException;
import com.amazonaws.services.kms.model.DependencyTimeoutException;
import com.amazonaws.services.kms.model.DisabledException;
import com.amazonaws.services.kms.model.InvalidGrantTokenException;
import com.amazonaws.services.kms.model.InvalidKeyUsageException;
import com.amazonaws.services.kms.model.KMSInternalException;
import com.amazonaws.services.kms.model.KMSInvalidSignatureException;
import com.amazonaws.services.kms.model.KMSInvalidStateException;
import com.amazonaws.services.kms.model.KeyUnavailableException;
import com.amazonaws.services.kms.model.MessageType;
import com.amazonaws.services.kms.model.NotFoundException;
import com.amazonaws.services.kms.model.VerifyRequest;
import com.amazonaws.services.kms.model.VerifyResult;
import com.google.common.collect.ImmutableSet;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.RemoteKeySourceException;
import com.nimbusds.jose.crypto.impl.CriticalHeaderParamsDeferral;
import com.nimbusds.jose.util.Base64URL;
import java.nio.ByteBuffer;
import java.util.Set;
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


@DisplayName("For KmsAsymmetricRsaSsaVerifier class,")
@ExtendWith(MockitoExtension.class)
public class KmsAsymmetricRsaSsaVerifierTest {

    private final EasyRandom random = new EasyRandom();

    @Mock
    private AWSKMS mockAwsKms;
    private String testPrivateKeyId;
    private MessageType testMessageType;
    private Set<String> testCriticalHeaders;

    private KmsAsymmetricRsaSsaVerifier kmsAsymmetricRsaSsaVerifier;

    @BeforeEach
    void setUp() {
        testPrivateKeyId = random.nextObject(String.class);
        testMessageType = random.nextObject(MessageType.class);
        testCriticalHeaders = ImmutableSet.of("test-critical-header");
    }

    @Nested
    @DisplayName("the getProcessedCriticalHeaderParams method,")
    class GetProcessedCriticalHeaderParams {
        @BeforeEach
        void beforeEach() {
            kmsAsymmetricRsaSsaVerifier = new KmsAsymmetricRsaSsaVerifier(
                    mockAwsKms, testPrivateKeyId, testMessageType);
        }

        @Test
        @DisplayName("should return processed critical headers.")
        void shouldReturnProcessedCriticalHeaders() {
            final Set<String> actualProcessedCriticalHeader =
                    kmsAsymmetricRsaSsaVerifier.getProcessedCriticalHeaderParams();
            assertThat(actualProcessedCriticalHeader)
                    .isEqualTo(new CriticalHeaderParamsDeferral().getProcessedCriticalHeaderParams());
        }
    }

    @Nested
    @DisplayName("the getDeferredCriticalHeaderParams method,")
    class GetDeferredCriticalHeaderParams {
        @BeforeEach
        void beforeEach() {
            kmsAsymmetricRsaSsaVerifier = new KmsAsymmetricRsaSsaVerifier(
                    mockAwsKms, testPrivateKeyId, testMessageType, testCriticalHeaders);
        }

        @Test
        @DisplayName("should return deferred critical headers.")
        void shouldReturnDeferredCriticalHeaders() {
            final Set<String> actualDeferredCriticalHeader =
                    kmsAsymmetricRsaSsaVerifier.getDeferredCriticalHeaderParams();
            assertThat(actualDeferredCriticalHeader).isEqualTo(testCriticalHeaders);
        }
    }

    @Nested
    @DisplayName("the verify method,")
    class VerifyMethod {

        private JWSHeader testJweHeader;
        private byte[] testSigningInput;
        private Base64URL testSignature;

        @Mock
        private ByteBuffer mockMessage;

        @BeforeEach
        void beforeEach() {
            testJweHeader = new JWSHeader.Builder(random.nextObject(JWSAlgorithm.class))
                    .criticalParams(testCriticalHeaders)
                    .build();

            testSigningInput = new byte[random.nextInt(512)];
            random.nextBytes(testSigningInput);

            mockMessage = ByteBuffer.allocate(random.nextInt(512));
            random.nextBytes(mockMessage.array());

            testSignature = random.nextObject(Base64URL.class);
        }

        @SneakyThrows
        private void mockGetMessage() {
            ReflectionSupport.invokeMethod(
                    kmsAsymmetricRsaSsaVerifier.getClass().getSuperclass()
                            .getDeclaredMethod("getMessage", JWSHeader.class, byte[].class),
                    doReturn(mockMessage).when(kmsAsymmetricRsaSsaVerifier),
                    testJweHeader,
                    testSigningInput);
        }

        @Nested
        @DisplayName("with critical header deferral policy failure,")
        class WithCriticalHeaderFailure {

            @BeforeEach
            void beforeEach() {
                kmsAsymmetricRsaSsaVerifier = spy(new KmsAsymmetricRsaSsaVerifier(
                        mockAwsKms, testPrivateKeyId, testMessageType));
            }

            @Test
            @DisplayName("should return false.")
            @SneakyThrows
            void shouldReturnFalse() {
                final boolean result =
                        kmsAsymmetricRsaSsaVerifier.verify(testJweHeader, testSigningInput, testSignature);
                assertThat(result).isFalse();
            }
        }

        @Nested
        @DisplayName("with critical header deferral policy pass,")
        class WithCriticalHeaderPass {

            @BeforeEach
            void beforeEach() {
                kmsAsymmetricRsaSsaVerifier = spy(new KmsAsymmetricRsaSsaVerifier(
                        mockAwsKms, testPrivateKeyId, testMessageType, testCriticalHeaders));
                mockGetMessage();
            }

            @Nested
            @DisplayName("with invalid signing key,")
            class WithInvalidSigningKey {

                @SneakyThrows
                AWSKMSException parameterizedBeforeEach(Class<AWSKMSException> invalidSigningExceptionClass) {
                    final var mockInvalidSigningException = mock(invalidSigningExceptionClass);
                    when(mockAwsKms
                            .verify(new VerifyRequest()
                                    .withKeyId(testPrivateKeyId)
                                    .withSigningAlgorithm(testJweHeader.getAlgorithm().toString())
                                    .withMessageType(testMessageType)
                                    .withMessage(mockMessage)
                                    .withSignature(ByteBuffer.wrap(testSignature.decode()))))
                            .thenThrow(mockInvalidSigningException);
                    return mockInvalidSigningException;
                }

                @ParameterizedTest
                @DisplayName("should throw RemoteKeySourceException.")
                @ValueSource(classes = {
                        NotFoundException.class, DisabledException.class, KeyUnavailableException.class,
                        InvalidKeyUsageException.class})
                void shouldThrowRemoteKeySourceException(Class<AWSKMSException> exceptionClass) {
                    final var mockInvalidSigningException = parameterizedBeforeEach(exceptionClass);
                    assertThatThrownBy(
                            () -> kmsAsymmetricRsaSsaVerifier.verify(testJweHeader, testSigningInput, testSignature))
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
                            .verify(new VerifyRequest()
                                    .withKeyId(testPrivateKeyId)
                                    .withSigningAlgorithm(testJweHeader.getAlgorithm().toString())
                                    .withMessageType(testMessageType)
                                    .withMessage(mockMessage)
                                    .withSignature(ByteBuffer.wrap(testSignature.decode()))))
                            .thenThrow(mockTemporaryKmsException);
                    return mockTemporaryKmsException;
                }

                @ParameterizedTest
                @DisplayName("should throw JOSEException.")
                @ValueSource(classes = {
                        DependencyTimeoutException.class, InvalidGrantTokenException.class, KMSInternalException.class,
                        KMSInvalidStateException.class})
                void shouldThrowJOSEException(Class<AWSKMSException> exceptionClass) {
                    final var mockInvalidSigningException = parameterizedBeforeEach(exceptionClass);
                    assertThatThrownBy(
                            () -> kmsAsymmetricRsaSsaVerifier.verify(testJweHeader, testSigningInput, testSignature))
                            .isInstanceOf(JOSEException.class)
                            .hasMessage("A temporary exception was thrown from KMS.")
                            .hasCause(mockInvalidSigningException);
                }
            }

            @Nested
            @DisplayName("with KMSInvalidSignatureException from KMS,")
            class WithKMSInvalidSignatureException {
                @Mock
                private KMSInvalidSignatureException mockKmsInvalidSignatureException;

                @BeforeEach
                void beforeEach() {
                    when(mockAwsKms
                            .verify(new VerifyRequest()
                                    .withKeyId(testPrivateKeyId)
                                    .withSigningAlgorithm(testJweHeader.getAlgorithm().toString())
                                    .withMessageType(testMessageType)
                                    .withMessage(mockMessage)
                                    .withSignature(ByteBuffer.wrap(testSignature.decode()))))
                            .thenThrow(mockKmsInvalidSignatureException);
                }

                @Test
                @DisplayName("should return false.")
                @SneakyThrows
                void shouldReturnFalse() {
                    final boolean result =
                            kmsAsymmetricRsaSsaVerifier.verify(testJweHeader, testSigningInput, testSignature);
                    assertThat(result).isFalse();
                }
            }

            @Nested
            @DisplayName("with invalid signature from KMS verification result,")
            class WithInvalidSignature {
                @Mock
                private VerifyResult mockVerifyResult;

                @BeforeEach
                void beforeEach() {
                    when(mockAwsKms
                            .verify(new VerifyRequest()
                                    .withKeyId(testPrivateKeyId)
                                    .withSigningAlgorithm(testJweHeader.getAlgorithm().toString())
                                    .withMessageType(testMessageType)
                                    .withMessage(mockMessage)
                                    .withSignature(ByteBuffer.wrap(testSignature.decode()))))
                            .thenReturn(mockVerifyResult);

                    when(mockVerifyResult.isSignatureValid()).thenReturn(false);
                }

                @Test
                @DisplayName("should return false.")
                @SneakyThrows
                void shouldReturnFalse() {
                    final boolean result =
                            kmsAsymmetricRsaSsaVerifier.verify(testJweHeader, testSigningInput, testSignature);
                    assertThat(result).isFalse();
                }
            }

            @Nested
            @DisplayName("with valid signature from KMS verification result,")
            class WithValidSignature {
                @Mock
                private VerifyResult mockVerifyResult;

                @BeforeEach
                void beforeEach() {
                    when(mockAwsKms
                            .verify(new VerifyRequest()
                                    .withKeyId(testPrivateKeyId)
                                    .withSigningAlgorithm(testJweHeader.getAlgorithm().toString())
                                    .withMessageType(testMessageType)
                                    .withMessage(mockMessage)
                                    .withSignature(ByteBuffer.wrap(testSignature.decode()))))
                            .thenReturn(mockVerifyResult);

                    when(mockVerifyResult.isSignatureValid()).thenReturn(true);
                }

                @Test
                @DisplayName("should return true.")
                @SneakyThrows
                void shouldReturnTrue() {
                    final boolean result =
                            kmsAsymmetricRsaSsaVerifier.verify(testJweHeader, testSigningInput, testSignature);
                    assertThat(result).isTrue();
                }
            }
        }
   }
}