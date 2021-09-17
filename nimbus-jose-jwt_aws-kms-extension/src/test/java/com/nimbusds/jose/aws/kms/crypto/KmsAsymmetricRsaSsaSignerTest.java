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
import com.amazonaws.services.kms.model.KMSInvalidStateException;
import com.amazonaws.services.kms.model.KeyUnavailableException;
import com.amazonaws.services.kms.model.MessageType;
import com.amazonaws.services.kms.model.NotFoundException;
import com.amazonaws.services.kms.model.SignRequest;
import com.amazonaws.services.kms.model.SignResult;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.RemoteKeySourceException;
import com.nimbusds.jose.aws.kms.exceptions.TemporaryJOSEException;
import com.nimbusds.jose.util.Base64URL;
import java.nio.ByteBuffer;
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

@DisplayName("For KmsAsymmetricRSASSASigner class,")
@ExtendWith(MockitoExtension.class)
public class KmsAsymmetricRsaSsaSignerTest {

    private final EasyRandom random = new EasyRandom();

    @Mock
    private AWSKMS mockAwsKms;
    private String testPrivateKeyId;
    private MessageType testMessageType;

    private KmsAsymmetricRSASSASigner kmsAsymmetricRsaSsaSigner;

    @BeforeEach
    void setUp() {
        testPrivateKeyId = random.nextObject(String.class);
        testMessageType = random.nextObject(MessageType.class);

        kmsAsymmetricRsaSsaSigner = spy(new KmsAsymmetricRSASSASigner(mockAwsKms, testPrivateKeyId, testMessageType));
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
                    kmsAsymmetricRsaSsaSigner.getClass().getSuperclass()
                            .getDeclaredMethod("getMessage", JWSHeader.class, byte[].class),
                    doReturn(mockMessage).when(kmsAsymmetricRsaSsaSigner),
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
                assertThatThrownBy(() -> kmsAsymmetricRsaSsaSigner.sign(testJweHeader, testSigningInput))
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
                assertThatThrownBy(() -> kmsAsymmetricRsaSsaSigner.sign(testJweHeader, testSigningInput))
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
                final var actualSignature = kmsAsymmetricRsaSsaSigner.sign(testJweHeader, testSigningInput);
                assertThat(actualSignature).isEqualTo(expectedSignature);
            }
        }
    }
}