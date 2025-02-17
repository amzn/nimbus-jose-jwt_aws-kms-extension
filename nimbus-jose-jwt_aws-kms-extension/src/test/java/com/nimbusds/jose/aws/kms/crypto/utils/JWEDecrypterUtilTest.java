package com.nimbusds.jose.aws.kms.crypto.utils;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.RemoteKeySourceException;
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
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.*;

import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

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
        private KmsClient mockAwsKms;
        private Map<String, String> testEncryptionContext;
        private JWEHeader testJweHeader;
        private final Base64URL testEncryptedKey = random.nextObject(Base64URL.class);
        private final Base64URL testIv = random.nextObject(Base64URL.class);
        private final Base64URL testCipherText = random.nextObject(Base64URL.class);
        private final Base64URL testAuthTag = random.nextObject(Base64URL.class);

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

            KmsException parameterizedBeforeEach(final Class<KmsException> invalidKeyExceptionClass) {
                final var invalidKeyException = mock(invalidKeyExceptionClass);
                when(mockAwsKms
                        .decrypt(DecryptRequest.builder()
                                .encryptionContext(testEncryptionContext)
                                .keyId(testKeyId)
                                .encryptionAlgorithm(testJweHeader.getAlgorithm().getName())
                                .ciphertextBlob(SdkBytes.fromByteBuffer(ByteBuffer.wrap(testEncryptedKey.decode())))
                                .build()))
                        .thenThrow(invalidKeyException);

                return invalidKeyException;
            }

            @ParameterizedTest
            @DisplayName("should throw RemoteKeySourceException.")
            @ValueSource(classes = {
                    NotFoundException.class, DisabledException.class, InvalidKeyUsageException.class,
                    KeyUnavailableException.class, KmsInvalidStateException.class})
            void shouldThrowRemoteKeySourceException(final Class<KmsException> invalidKeyExceptionClass) {
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

            KmsException parameterizedBeforeEach(final Class<KmsException> temporaryKMSExceptionClass) {
                final var temporaryKMSException = mock(temporaryKMSExceptionClass);
                when(mockAwsKms
                        .decrypt(DecryptRequest.builder()
                                .encryptionContext(testEncryptionContext)
                                .keyId(testKeyId)
                                .encryptionAlgorithm(testJweHeader.getAlgorithm().getName())
                                .ciphertextBlob(SdkBytes.fromByteBuffer(ByteBuffer.wrap(testEncryptedKey.decode())))
                                .build()))
                        .thenThrow(temporaryKMSException);

                return temporaryKMSException;
            }

            @ParameterizedTest
            @DisplayName("should throw TemporaryJOSEException.")
            @ValueSource(classes = {
                    DependencyTimeoutException.class, InvalidGrantTokenException.class,
                    KmsInternalException.class})
            void shouldThrowRemoteKeySourceException(final Class<KmsException> invalidKeyExceptionClass) {
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

            private final DecryptResponse testDecryptResult = DecryptResponse.builder().plaintext(SdkBytes.fromString("test", Charset.defaultCharset())).build();
            private final MockedStatic<ContentCryptoProvider> mockContentCryptoProvider =
                    mockStatic(ContentCryptoProvider.class);
            private final byte[] expectedData = new byte[random.nextInt(512)];

            @BeforeEach
            void beforeEach() {
                when(mockAwsKms
                        .decrypt(DecryptRequest.builder()
                                .encryptionContext(testEncryptionContext)
                                .keyId(testKeyId)
                                .encryptionAlgorithm(testJweHeader.getAlgorithm().getName())
                                .ciphertextBlob(SdkBytes.fromByteBuffer(ByteBuffer.wrap(testEncryptedKey.decode())))
                                .build()))
                        .thenReturn(testDecryptResult);

                random.nextBytes(expectedData);
                mockContentCryptoProvider.when(
                                () -> ContentCryptoProvider.decrypt(
                                        testJweHeader, testEncryptedKey, testIv, testCipherText, testAuthTag,
                                        new SecretKeySpec(
                                                testDecryptResult.plaintext().asByteArray(),
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
