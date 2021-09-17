package com.nimbusds.jose.aws.kms.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.refEq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.AWSKMSException;
import com.amazonaws.services.kms.model.DependencyTimeoutException;
import com.amazonaws.services.kms.model.DisabledException;
import com.amazonaws.services.kms.model.EncryptionAlgorithmSpec;
import com.amazonaws.services.kms.model.GenerateDataKeyRequest;
import com.amazonaws.services.kms.model.GenerateDataKeyResult;
import com.amazonaws.services.kms.model.InvalidGrantTokenException;
import com.amazonaws.services.kms.model.InvalidKeyUsageException;
import com.amazonaws.services.kms.model.KMSInternalException;
import com.amazonaws.services.kms.model.KMSInvalidStateException;
import com.amazonaws.services.kms.model.KeyUnavailableException;
import com.amazonaws.services.kms.model.NotFoundException;
import com.google.common.collect.ImmutableMap;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWECryptoParts;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.RemoteKeySourceException;
import com.nimbusds.jose.aws.kms.crypto.impl.KmsSymmetricCryptoProvider;
import com.nimbusds.jose.aws.kms.exceptions.TemporaryJOSEException;
import com.nimbusds.jose.crypto.impl.AlgorithmSupportMessage;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.util.Base64URL;
import java.nio.ByteBuffer;
import java.util.Map;
import javax.crypto.spec.SecretKeySpec;
import lombok.SneakyThrows;
import lombok.var;
import org.jeasy.random.EasyRandom;
import org.jeasy.random.EasyRandomParameters;
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

@DisplayName("For KmsSymmetricEncrypter class,")
@ExtendWith(MockitoExtension.class)
class KmsSymmetricEncrypterTest {

    private EasyRandom random = new EasyRandom(new EasyRandomParameters()
            .randomize(ByteBuffer.class, () -> {
                final var random = new EasyRandom();
                final var byteBuffer = ByteBuffer.allocate(random.nextInt(512));
                random.nextBytes(byteBuffer.array());
                return byteBuffer;
            }));

    @Mock
    private AWSKMS mockAwsKms;
    private final String testKeyId = random.nextObject(String.class);
    private final Map<String, String> testEncryptionContext = random.nextObject(Map.class);

    private KmsSymmetricEncrypter kmsSymmetricEncrypter;

    @BeforeEach
    void beforeEach() {
        kmsSymmetricEncrypter = new KmsSymmetricEncrypter(mockAwsKms, testKeyId, testEncryptionContext);
    }

    @Nested
    @DisplayName("the encrypt method,")
    class EncryptMethod {

        private JWEHeader testJweHeader;
        private final byte[] testClearText = new byte[random.nextInt(512)];

        @BeforeEach
        void beforeEach() {
            random.nextBytes(testClearText);
        }

        @Nested
        @DisplayName("with unsupported algorithm,")
        class WithUnsupportedAlgorithm {

            @BeforeEach
            void beforeEach() {
                testJweHeader = new JWEHeader.Builder(
                        JWEAlgorithm.parse("Unsupported Algorithm"),
                        EncryptionMethod.A256GCM)
                        .build();
            }

            @Test
            @DisplayName("should throw JOSEException.")
            void shouldThrowJOSEException() {
                assertThatThrownBy(() -> kmsSymmetricEncrypter.encrypt(testJweHeader, testClearText))
                        .isInstanceOf(JOSEException.class)
                        .hasMessage(AlgorithmSupportMessage.unsupportedJWEAlgorithm(
                                testJweHeader.getAlgorithm(), KmsSymmetricCryptoProvider.SUPPORTED_ALGORITHMS))
                        .hasNoCause();
            }
        }

        @Nested
        @DisplayName("with supported algorithm,")
        class WithSupportedAlgorithm {

            @Nested
            @DisplayName("with unsupported encryption method,")
            class WithUnsupportedEncryptionMethod {

                @BeforeEach
                void beforeEach() {
                    testJweHeader = new JWEHeader.Builder(
                            JWEAlgorithm.parse(EncryptionAlgorithmSpec.SYMMETRIC_DEFAULT.toString()),
                            EncryptionMethod.parse("Unsupported Encryption Method"))
                            .build();
                }

                @Test
                @DisplayName("should throw JOSEException.")
                void shouldThrowJOSEException() {
                    assertThatThrownBy(() -> kmsSymmetricEncrypter.encrypt(testJweHeader, testClearText))
                            .isInstanceOf(JOSEException.class)
                            .hasMessage(AlgorithmSupportMessage.unsupportedEncryptionMethod(
                                    testJweHeader.getEncryptionMethod(),
                                    KmsSymmetricCryptoProvider.SUPPORTED_ENCRYPTION_METHODS))
                            .hasNoCause();
                }
            }

            @Nested
            @DisplayName("with supported encryption method,")
            class WithSupportedEncryptionMethod {

                @BeforeEach
                void beforeEach() {
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
                                .generateDataKey(new GenerateDataKeyRequest()
                                        .withKeyId(testKeyId)
                                        .withKeySpec(
                                                KmsSymmetricCryptoProvider.ENCRYPTION_METHOD_TO_DATA_KEY_SPEC_MAP.get(
                                                        testJweHeader.getEncryptionMethod()))
                                        .withEncryptionContext(testEncryptionContext)))
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
                        assertThatThrownBy(() -> kmsSymmetricEncrypter.encrypt(testJweHeader, testClearText))
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
                                .generateDataKey(new GenerateDataKeyRequest()
                                        .withKeyId(testKeyId)
                                        .withKeySpec(
                                                KmsSymmetricCryptoProvider.ENCRYPTION_METHOD_TO_DATA_KEY_SPEC_MAP.get(
                                                        testJweHeader.getEncryptionMethod()))
                                        .withEncryptionContext(testEncryptionContext)))
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
                        assertThatThrownBy(() -> kmsSymmetricEncrypter.encrypt(testJweHeader, testClearText))
                                .isInstanceOf(TemporaryJOSEException.class)
                                .hasMessage("A temporary error was thrown from KMS.")
                                .hasCause(invalidKeyException);
                    }
                }

                @Nested
                @DisplayName("with data-key from KMS,")
                class WithDataKey {

                    private GenerateDataKeyResult testGenerateDataKeyResult;
                    private final MockedStatic<ContentCryptoProvider> mockContentCryptoProvider =
                            mockStatic(ContentCryptoProvider.class);

                    @Mock
                    private JWECryptoParts mockJweCryptoParts;

                    @BeforeEach
                    void beforeEach() {
                        testGenerateDataKeyResult = random.nextObject(GenerateDataKeyResult.class);
                        when(mockAwsKms
                                .generateDataKey(new GenerateDataKeyRequest()
                                        .withKeyId(testKeyId)
                                        .withKeySpec(
                                                KmsSymmetricCryptoProvider.ENCRYPTION_METHOD_TO_DATA_KEY_SPEC_MAP.get(
                                                        testJweHeader.getEncryptionMethod()))
                                        .withEncryptionContext(testEncryptionContext)))
                                .thenReturn(testGenerateDataKeyResult);
                    }

                    @Nested
                    @DisplayName("without encryption context,")
                    class WithoutEncryptionContext {

                        @BeforeEach
                        void beforeEach() {
                            kmsSymmetricEncrypter = new KmsSymmetricEncrypter(mockAwsKms, testKeyId);
                            mockContentCryptoProvider.when(
                                            () -> ContentCryptoProvider.encrypt(
                                                    testJweHeader,
                                                    testClearText,
                                                    new SecretKeySpec(testGenerateDataKeyResult.getPlaintext().array(),
                                                            testJweHeader.getAlgorithm().toString()),
                                                    Base64URL.encode(testGenerateDataKeyResult.getCiphertextBlob().array()),
                                                    kmsSymmetricEncrypter.getJCAContext()))
                                    .thenReturn(mockJweCryptoParts);
                        }

                        @Test
                        @DisplayName("should encrypted JWE token.")
                        @SneakyThrows
                        void shouldReturnEncryptedJWEToken() {
                            final JWECryptoParts actualJweCryptoParts =
                                    kmsSymmetricEncrypter.encrypt(testJweHeader, testClearText);
                            assertThat(actualJweCryptoParts).isSameAs(mockJweCryptoParts);
                        }

                    }

                    @Nested
                    @DisplayName("without encryption context,")
                    class WithEncryptionContext {

                        @BeforeEach
                        void beforeEach() {
                            mockContentCryptoProvider.when(
                                    () -> ContentCryptoProvider.encrypt(
                                                    refEq(new JWEHeader.Builder(testJweHeader)
                                                            .customParams(ImmutableMap.of(
                                                                    KmsSymmetricCryptoProvider
                                                                            .ENCRYPTION_CONTEXT_HEADER,
                                                                    testEncryptionContext))
                                                            .build()),
                                                    eq(testClearText),
                                                    eq(new SecretKeySpec(
                                                            testGenerateDataKeyResult.getPlaintext().array(),
                                                            testJweHeader.getAlgorithm().toString())),
                                                    eq(Base64URL.encode(
                                                            testGenerateDataKeyResult.getCiphertextBlob().array())),
                                                    eq(kmsSymmetricEncrypter.getJCAContext())))
                                            .thenReturn(mockJweCryptoParts);
                        }

                        @Test
                        @DisplayName("should encrypted JWE token.")
                        @SneakyThrows
                        void shouldReturnEncryptedJWEToken() {
                            final JWECryptoParts actualJweCryptoParts =
                                    kmsSymmetricEncrypter.encrypt(testJweHeader, testClearText);
                            assertThat(actualJweCryptoParts).isSameAs(mockJweCryptoParts);
                        }

                    }

                    @AfterEach
                    void afterEach() {
                        mockContentCryptoProvider.close();
                    }
                }
            }
        }
    }
}
