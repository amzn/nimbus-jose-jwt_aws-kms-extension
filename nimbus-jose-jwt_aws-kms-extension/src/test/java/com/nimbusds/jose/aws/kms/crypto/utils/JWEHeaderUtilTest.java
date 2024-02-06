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

package com.nimbusds.jose.aws.kms.crypto.utils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.amazonaws.services.kms.model.EncryptionAlgorithmSpec;
import com.google.common.collect.ImmutableSet;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.aws.kms.crypto.testUtils.EasyRandomTestUtils;
import com.nimbusds.jose.crypto.impl.AlgorithmSupportMessage;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import java.util.Map;
import java.util.Set;
import org.jeasy.random.EasyRandom;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("For the JWEHeaderUtil class,")
class JWEHeaderUtilTest {
    private final EasyRandom random = EasyRandomTestUtils.getEasyRandomWithByteBufferSupport();

    @Nested
    @DisplayName("the validateJWEHeaderAlgorithms method,")
    class ValidateJWEHeaderMethod {

        private JWEHeader testJweHeader;

        public final Set<JWEAlgorithm> testSupportedAlgorithms = ImmutableSet.of(
                JWEAlgorithm.parse(EncryptionAlgorithmSpec.SYMMETRIC_DEFAULT.name()),
                JWEAlgorithm.parse(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_1.name()),
                JWEAlgorithm.parse(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256.name()));

        public final Set<EncryptionMethod> testSupportedEncryptionMethods =
                ContentCryptoProvider.SUPPORTED_ENCRYPTION_METHODS;

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
                assertThatThrownBy(() -> JWEHeaderUtil.validateJWEHeaderAlgorithms(
                                testJweHeader, testSupportedAlgorithms, testSupportedEncryptionMethods))
                        .isInstanceOf(JOSEException.class)
                        .hasMessage(AlgorithmSupportMessage.unsupportedJWEAlgorithm(
                                testJweHeader.getAlgorithm(), testSupportedAlgorithms))
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
                    assertThatThrownBy(() -> JWEHeaderUtil.validateJWEHeaderAlgorithms(
                            testJweHeader, testSupportedAlgorithms, testSupportedEncryptionMethods))
                            .isInstanceOf(JOSEException.class)
                            .hasMessage(AlgorithmSupportMessage.unsupportedEncryptionMethod(
                                    testJweHeader.getEncryptionMethod(),
                                    testSupportedEncryptionMethods))
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

                @Test
                @DisplayName("shouldn't throw any exception.")
                void shouldThrowException() {
                    assertThatNoException()
                            .isThrownBy(() -> JWEHeaderUtil.validateJWEHeaderAlgorithms(
                                    testJweHeader, testSupportedAlgorithms, testSupportedEncryptionMethods));
                }
            }
        }
    }

    @Nested
    @DisplayName("the getJWEHeaderWithEncryptionContext method,")
    class GetJWEHeaderWithEncryptionContextMethod {

        private JWEHeader testHeader;

        private String testEncryptionContextHeaderName;

        private Map<String, String> testEncryptionContext;

        @BeforeEach
        void beforeEach() {
            testHeader = new JWEHeader.Builder(
                    random.nextObject(JWEAlgorithm.class), random.nextObject(EncryptionMethod.class))
                    .build();
            testEncryptionContextHeaderName = random.nextObject(String.class);
        }

        @Nested
        @DisplayName("with null encryption context,")
        class WithNullContext {
            @Test
            @DisplayName("should return the input header.")
            void shouldReturnInputHeader() {
                final JWEHeader updatedHeader = JWEHeaderUtil.getJWEHeaderWithEncryptionContext(
                        testHeader, testEncryptionContextHeaderName, testEncryptionContext);

                assertThat(updatedHeader).isSameAs(testHeader);
            }
        }

        @Nested
        @DisplayName("with non-null encryption context,")
        class WithNonNullContext {
            @BeforeEach
            void beforeEach() {
                testEncryptionContext = random.nextObject(Map.class);
            }
            @Test
            @DisplayName("should return the updated header with encryption context.")
            void shouldReturnUpdatedHeader() {
                final JWEHeader updatedHeader = JWEHeaderUtil.getJWEHeaderWithEncryptionContext(
                        testHeader, testEncryptionContextHeaderName, testEncryptionContext);

                assertThat(updatedHeader.getAlgorithm()).isEqualTo(testHeader.getAlgorithm());
                assertThat(updatedHeader.getEncryptionMethod()).isEqualTo(testHeader.getEncryptionMethod());
                assertThat(updatedHeader.getCustomParam(testEncryptionContextHeaderName))
                        .isEqualTo(testEncryptionContext);
            }
        }
    }
}
