package com.nimbusds.jose.crypto.impl;

import java.util.Collections;
import java.util.Set;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEProvider;
import com.nimbusds.jose.jca.JWEJCAContext;


/**
 * Note: This class exists to make the {@link BaseJWEProvider} class public.
 * TODO: Rais a pull-request to Nimbus to make {@link BaseJWEProvider} class public.
 *
 * The base abstract class for JSON Web Encryption (JWE) encrypters and
 * decrypters.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-11-16
 */
public abstract class PublicBaseJWEProvider extends BaseJWEProvider {

    /**
     * Creates a new base JWE provider.
     *
     * @param algs The supported algorithms by the JWE provider instance.
     *             Must not be {@code null}.
     * @param encs The supported encryption methods by the JWE provider
     *             instance. Must not be {@code null}.
     */
    public PublicBaseJWEProvider(final Set<JWEAlgorithm> algs,
            final Set<EncryptionMethod> encs) {
        super(algs, encs);
    }
}
