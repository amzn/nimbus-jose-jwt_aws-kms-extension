package com.nimbusds.jose.aws.kms.crypto.impl;

import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.DecryptResult;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.aws.kms.crypto.KmsDecryptOperation;
import com.nimbusds.jose.aws.kms.crypto.impl.models.CacheConfiguration;
import java.time.Duration;
import java.util.concurrent.ExecutionException;
import lombok.NonNull;


public class LoadingCachedKmsDecryptOperation implements KmsDecryptOperation {

    @NonNull
    private final KmsDecryptOperation kmsDecryptOperation;

    @NonNull
    private final LoadingCache<DecryptRequest, DecryptResult> dataKeyLoadingCache;

    public LoadingCachedKmsDecryptOperation(@NonNull final KmsDecryptOperation kmsDecryptOperation) {
        this(kmsDecryptOperation, CacheConfiguration.builder()
                .expireAfterWrite(Duration.ofMinutes(30))
                .maximumSize(100)
                .build());
    }

    public LoadingCachedKmsDecryptOperation(
            @NonNull final KmsDecryptOperation kmsDecryptOperation,
            @NonNull final CacheConfiguration cacheConfiguration) {
        this.kmsDecryptOperation = kmsDecryptOperation;
        this.dataKeyLoadingCache = CacheBuilder.newBuilder()
                .expireAfterWrite(cacheConfiguration.getExpireAfterWrite())
                .maximumSize(cacheConfiguration.getMaximumSize())
                .build(new CacheLoader<DecryptRequest, DecryptResult>() {
                    @Override
                    public DecryptResult load(@NonNull final DecryptRequest request) throws Exception {
                        return kmsDecryptOperation.decrypt(request);
                    }
                });
    }

    @Override
    public DecryptResult decrypt(@NonNull final DecryptRequest request) throws JOSEException {
        try {
            return dataKeyLoadingCache.get(request);
        } catch (ExecutionException e) {
            throw new JOSEException("Error occurred while calling `get()` on `dataKeyLoadingCache`.", e);
        }
    }
}
