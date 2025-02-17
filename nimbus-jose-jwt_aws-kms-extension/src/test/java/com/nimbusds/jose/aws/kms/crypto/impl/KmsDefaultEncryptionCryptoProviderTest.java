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

import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.aws.kms.crypto.utils.JWEHeaderUtil;
import org.jeasy.random.EasyRandom;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.services.kms.KmsClient;

import java.util.Map;

import static org.mockito.Mockito.*;

@DisplayName("For KmsDefaultEncryptionCryptoProvider class,")
@ExtendWith(MockitoExtension.class)
class KmsDefaultEncryptionCryptoProviderTest {

    private final EasyRandom random = new EasyRandom();

    @Mock
    private KmsClient mockAwsKms;
    private final String testPrivateKeyId = random.nextObject(String.class);

    private KmsDefaultEncryptionCryptoProvider kmsDefaultEncryptionCryptoProvider;

    @BeforeEach
    void beforeEach() {
        kmsDefaultEncryptionCryptoProvider = mock(KmsDefaultEncryptionCryptoProvider.class,
                withSettings().useConstructor(mockAwsKms, testPrivateKeyId).defaultAnswer(CALLS_REAL_METHODS));
    }

    @Nested
    @DisplayName("the validateJWEHeader method,")
    class ValidateJWEHeaderMethod {

        @Mock
        private JWEHeader testJweHeader;

        private MockedStatic<JWEHeaderUtil> mockJweHeaderValidationUtil;

        @BeforeEach
        void beforeEach() {
            mockJweHeaderValidationUtil = mockStatic(JWEHeaderUtil.class);
        }

        @AfterEach
        void afterEach() {
            mockJweHeaderValidationUtil.close();
        }

        @Nested
        @DisplayName("without encryption context,")
        class WithoutEncryptionContext {

            @Test
            @DisplayName("should call `JWEHeaderUtil.validateJWEHeaderAlgorithms`.")
            void shouldThrowException() throws Exception {
                kmsDefaultEncryptionCryptoProvider.validateJWEHeader(testJweHeader);
                mockJweHeaderValidationUtil.verify(() -> JWEHeaderUtil.validateJWEHeaderAlgorithms(
                        testJweHeader,
                        KmsDefaultEncryptionCryptoProvider.SUPPORTED_ALGORITHMS,
                        KmsDefaultEncryptionCryptoProvider.SUPPORTED_ENCRYPTION_METHODS));

            }
        }

        @Nested
        @DisplayName("with encryption context,")
        class WithEncryptionContext {

            @BeforeEach
            void beforeEach() {
                kmsDefaultEncryptionCryptoProvider = mock(KmsDefaultEncryptionCryptoProvider.class, withSettings()
                        .useConstructor(mockAwsKms, testPrivateKeyId, mock(Map.class))
                        .defaultAnswer(CALLS_REAL_METHODS));
            }

            @Test
            @DisplayName("should call `JWEHeaderUtil.validateJWEHeaderAlgorithms`.")
            void shouldThrowException() throws Exception {
                kmsDefaultEncryptionCryptoProvider.validateJWEHeader(testJweHeader);
                mockJweHeaderValidationUtil.verify(() -> JWEHeaderUtil.validateJWEHeaderAlgorithms(
                        testJweHeader,
                        KmsDefaultEncryptionCryptoProvider.SUPPORTED_ALGORITHMS,
                        KmsDefaultEncryptionCryptoProvider.SUPPORTED_ENCRYPTION_METHODS));

            }
        }
    }
}
