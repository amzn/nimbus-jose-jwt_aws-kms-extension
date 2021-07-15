/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.nimbusds.jose.aws.kms.crypto.impl;


import com.amazonaws.services.kms.model.SigningAlgorithmSpec;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.impl.BaseJWSProvider;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import org.apache.commons.codec.digest.MessageDigestAlgorithms;

public abstract class KmsAsymmetricRsaSsaProvider extends BaseJWSProvider {

    /**
     * The supported JWS algorithms by the RSA-SSA provider class.
     */
    public static final Set<JWSAlgorithm> SUPPORTED_ALGORITHMS;

    public static final Map<JWSAlgorithm, String> JWS_ALGORITHM_TO_MESSAGE_DIGEST_ALGORITHM = Map.ofEntries(
            Map.entry(JWSAlgorithm.parse(SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256.toString()),
                    MessageDigestAlgorithms.SHA_256),
            Map.entry(JWSAlgorithm.parse(SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_384.toString()),
                    MessageDigestAlgorithms.SHA_384),
            Map.entry(JWSAlgorithm.parse(SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_512.toString()),
                    MessageDigestAlgorithms.SHA_512),
            Map.entry(JWSAlgorithm.parse(SigningAlgorithmSpec.RSASSA_PSS_SHA_256.toString()),
                    MessageDigestAlgorithms.SHA_256),
            Map.entry(JWSAlgorithm.parse(SigningAlgorithmSpec.RSASSA_PSS_SHA_384.toString()),
                    MessageDigestAlgorithms.SHA_384),
            Map.entry(JWSAlgorithm.parse(SigningAlgorithmSpec.RSASSA_PSS_SHA_512.toString()),
                    MessageDigestAlgorithms.SHA_512));


    static {
        Set<JWSAlgorithm> algs = new LinkedHashSet<>();
        algs.add(JWSAlgorithm.parse(SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256.toString()));
        algs.add(JWSAlgorithm.parse(SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_384.toString()));
        algs.add(JWSAlgorithm.parse(SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_512.toString()));
        algs.add(JWSAlgorithm.parse(SigningAlgorithmSpec.RSASSA_PSS_SHA_256.toString()));
        algs.add(JWSAlgorithm.parse(SigningAlgorithmSpec.RSASSA_PSS_SHA_384.toString()));
        algs.add(JWSAlgorithm.parse(SigningAlgorithmSpec.RSASSA_PSS_SHA_512.toString()));
        SUPPORTED_ALGORITHMS = Collections.unmodifiableSet(algs);
    }


    /**
     * Creates a new RSASSA provider.
     */
    protected KmsAsymmetricRsaSsaProvider() {

        super(SUPPORTED_ALGORITHMS);
    }
}
