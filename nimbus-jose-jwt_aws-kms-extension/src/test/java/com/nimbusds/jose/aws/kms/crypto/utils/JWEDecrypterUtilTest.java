package com.nimbusds.jose.aws.kms.crypto.utils;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClient;
import com.amazonaws.services.kms.model.*;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.RemoteKeySourceException;
import com.nimbusds.jose.aws.kms.crypto.testUtils.EasyRandomTestUtils;
import com.nimbusds.jose.aws.kms.exceptions.TemporaryJOSEException;
import com.nimbusds.jose.jca.JWEJCAContext;
import com.nimbusds.jose.util.Base64URL;

import java.nio.ByteBuffer;
import java.util.Map;
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

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.when;

@DisplayName("For the JWEDecrypterUtil class,")
@ExtendWith(MockitoExtension.class)
public class JWEDecrypterUtilTest {

    @Nested
    @DisplayName("the decrypt method,")
    class DecryptMethod {

        private final EasyRandom random = EasyRandomTestUtils.getEasyRandomWithByteBufferSupport();
        private String testKeyId;
        @Mock
        private JWEJCAContext mockJWEJCAContext;
        @Mock
        private AWSKMS mockAwsKms;
        private Map<String, String> testEncryptionContext;
        private JWEHeader testJweHeader;
        private Base64URL testEncryptedKey = random.nextObject(Base64URL.class);
        private Base64URL testIv = random.nextObject(Base64URL.class);
        private Base64URL testCipherText = random.nextObject(Base64URL.class);
        private Base64URL testAuthTag = random.nextObject(Base64URL.class);

        @BeforeEach
        void setUp() {
            testKeyId = random.nextObject(String.class);
            testEncryptionContext = random.nextObject(Map.class);
            testJweHeader = new JWEHeader.Builder(
                    JWEAlgorithm.parse(EncryptionAlgorithmSpec.SYMMETRIC_DEFAULT.toString()),
                    EncryptionMethod.A256GCM)
                    .build();
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
                                .withEncryptionAlgorithm(testJweHeader.getAlgorithm().getName())
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
                        () -> JWEDecrypterUtil.decrypt(mockAwsKms, testKeyId, testEncryptionContext, testJweHeader,
                                testEncryptedKey, testIv, testCipherText, testAuthTag, mockJWEJCAContext))
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
                                .withEncryptionAlgorithm(testJweHeader.getAlgorithm().getName())
                                .withCiphertextBlob(ByteBuffer.wrap(testEncryptedKey.decode()))))
                        .thenThrow(temporaryKMSException);

                return temporaryKMSException;
            }

            @ParameterizedTest
            @DisplayName("should throw TemporaryJOSEException.")
            @ValueSource(classes = {
                    DependencyTimeoutException.class, InvalidGrantTokenException.class,
                    KMSInternalException.class})
            void shouldThrowRemoteKeySourceException(final Class<AWSKMSException> invalidKeyExceptionClass) {
                final var invalidKeyException = parameterizedBeforeEach(invalidKeyExceptionClass);
                assertThatThrownBy(
                        () -> JWEDecrypterUtil.decrypt(mockAwsKms, testKeyId, testEncryptionContext, testJweHeader,
                                testEncryptedKey, testIv, testCipherText, testAuthTag, mockJWEJCAContext))
                        .isInstanceOf(TemporaryJOSEException.class)
                        .hasMessage("A temporary error was thrown from KMS.")
                        .hasCause(invalidKeyException);
            }
        }
    }
}