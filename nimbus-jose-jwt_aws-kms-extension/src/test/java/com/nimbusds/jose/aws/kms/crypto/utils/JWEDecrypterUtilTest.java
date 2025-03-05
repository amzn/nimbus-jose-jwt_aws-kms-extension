package com.nimbusds.jose.aws.kms.crypto.utils;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.AWSKMSException;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.DecryptResult;
import com.amazonaws.services.kms.model.DependencyTimeoutException;
import com.amazonaws.services.kms.model.DisabledException;
import com.amazonaws.services.kms.model.EncryptionAlgorithmSpec;
import com.amazonaws.services.kms.model.InvalidGrantTokenException;
import com.amazonaws.services.kms.model.InvalidKeyUsageException;
import com.amazonaws.services.kms.model.KeyUnavailableException;
import com.amazonaws.services.kms.model.KMSInternalException;
import com.amazonaws.services.kms.model.KMSInvalidStateException;
import com.amazonaws.services.kms.model.NotFoundException;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.RemoteKeySourceException;
import com.nimbusds.jose.aws.kms.crypto.testUtils.EasyRandomTestUtils;
import com.nimbusds.jose.aws.kms.exceptions.TemporaryJOSEException;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.jca.JWEJCAContext;
import com.nimbusds.jose.util.Base64URL;
import java.nio.ByteBuffer;
import java.util.Map;
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
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.nimbusds.jose.aws.kms.crypto.impl.KmsDefaultEncryptionCryptoProvider.JWE_TO_KMS_ALGORITHM_SPEC;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.assertj.core.api.Assertions.assertThat;

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
                    JWEAlgorithm.RSA_OAEP_256,
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
                                .withEncryptionAlgorithm(JWE_TO_KMS_ALGORITHM_SPEC.get(testJweHeader.getAlgorithm()))
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
                                .withEncryptionAlgorithm(JWE_TO_KMS_ALGORITHM_SPEC.get(testJweHeader.getAlgorithm()))
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

        @Nested
        @DisplayName("with decryption result,")
        class WithDecryptionResult {

            private final DecryptResult testDecryptResult = random.nextObject(DecryptResult.class);
            private final MockedStatic<ContentCryptoProvider> mockContentCryptoProvider =
                    mockStatic(ContentCryptoProvider.class);
            private final byte[] expectedData = new byte[random.nextInt(512)];

            @BeforeEach
            void beforeEach() {
                when(mockAwsKms
                        .decrypt(new DecryptRequest()
                                .withEncryptionContext(testEncryptionContext)
                                .withKeyId(testKeyId)
                                .withEncryptionAlgorithm(JWE_TO_KMS_ALGORITHM_SPEC.get(testJweHeader.getAlgorithm()))
                                .withCiphertextBlob(ByteBuffer.wrap(testEncryptedKey.decode()))))
                        .thenReturn(testDecryptResult);

                random.nextBytes(expectedData);
                mockContentCryptoProvider.when(
                                () -> ContentCryptoProvider.decrypt(
                                        testJweHeader, testEncryptedKey, testIv, testCipherText, testAuthTag,
                                        new SecretKeySpec(
                                                testDecryptResult.getPlaintext().array(),
                                                testJweHeader.getAlgorithm().toString()),
                                        mockJWEJCAContext))
                        .thenReturn(expectedData);
            }

            @Test
            @SneakyThrows
            @DisplayName("should return decrypted data,")
            void shouldReturnDecryptedData() {
                final byte[] actualData = JWEDecrypterUtil.decrypt(mockAwsKms, testKeyId, testEncryptionContext,
                        testJweHeader, testEncryptedKey, testIv, testCipherText, testAuthTag, mockJWEJCAContext);
                assertThat(actualData).isEqualTo(expectedData);
            }

            @AfterEach
            @SneakyThrows
            void afterEach() {
                mockContentCryptoProvider.close();
            }
        }
    }
}