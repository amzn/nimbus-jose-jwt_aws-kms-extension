package com.nimbusds.jose.aws.kms.crypto.impl;

import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.EncryptionAlgorithmSpec;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.impl.AlgorithmSupportMessage;
import java.util.Map;
import org.jeasy.random.EasyRandom;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@DisplayName("For KmsSymmetricCryptoProvider class,")
@ExtendWith(MockitoExtension.class)
class KmsSymmetricCryptoProviderTest {

    private EasyRandom random = new EasyRandom();

    @Mock
    private AWSKMS mockAwsKms;
    private String testPrivateKeyId = random.nextObject(String.class);

    private KmsSymmetricCryptoProvider kmsSymmetricCryptoProvider;

    @BeforeEach
    void beforeEach() {
        kmsSymmetricCryptoProvider = mock(KmsSymmetricCryptoProvider.class,
                withSettings().useConstructor(mockAwsKms, testPrivateKeyId).defaultAnswer(CALLS_REAL_METHODS));
    }

    @Nested
    @DisplayName("the validateJWEHeader method,")
    class ValidateJWEHeaderMethod {

        private JWEHeader testJweHeader;

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
                assertThatThrownBy(() -> kmsSymmetricCryptoProvider.validateJWEHeader(testJweHeader))
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
                    assertThatThrownBy(() -> kmsSymmetricCryptoProvider.validateJWEHeader(testJweHeader))
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
                @DisplayName("without encryption context,")
                class WithoutEncryptionContext {

                    @Test
                    @DisplayName("shouldn't throw any exception.")
                    void shouldThrowException() {
                        assertThatNoException()
                                .isThrownBy(() -> kmsSymmetricCryptoProvider.validateJWEHeader(testJweHeader));
                    }
                }

                @Nested
                @DisplayName("with encryption context,")
                class WithEncryptionContext {

                    @BeforeEach
                    void beforeEach() {
                        kmsSymmetricCryptoProvider = mock(KmsSymmetricCryptoProvider.class, withSettings()
                                .useConstructor(mockAwsKms, testPrivateKeyId, mock(Map.class))
                                .defaultAnswer(CALLS_REAL_METHODS));
                    }

                    @Test
                    @DisplayName("shouldn't throw any exception.")
                    void shouldThrowException() {
                        assertThatNoException()
                                .isThrownBy(() -> kmsSymmetricCryptoProvider.validateJWEHeader(testJweHeader));
                    }
                }
            }
        }
    }
}