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

package com.nimbusds.jose.crypto.impl;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import java.util.Set;


/**
 * Note: This class exists to make the {@link BaseJWEProvider} class public. TODO: Rais a pull-request to Nimbus to make
 * {@link BaseJWEProvider} class public.
 * <p>
 * The base abstract class for JSON Web Encryption (JWE) encrypters and decrypters.
 */
public abstract class PublicBaseJWEProvider extends BaseJWEProvider {

    /**
     * Creates a new base JWE provider.
     *
     * @param algs The supported algorithms by the JWE provider instance. Must not be {@code null}.
     * @param encs The supported encryption methods by the JWE provider instance. Must not be {@code null}.
     */
    public PublicBaseJWEProvider(final Set<JWEAlgorithm> algs,
            final Set<EncryptionMethod> encs) {
        super(algs, encs);
    }
}
