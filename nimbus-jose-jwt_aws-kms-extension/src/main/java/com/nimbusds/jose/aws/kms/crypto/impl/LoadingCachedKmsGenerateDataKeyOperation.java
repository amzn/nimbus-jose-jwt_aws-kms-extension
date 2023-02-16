package com.nimbusds.jose.aws.kms.crypto.impl;

import com.amazonaws.services.kms.model.GenerateDataKeyRequest;
import com.amazonaws.services.kms.model.GenerateDataKeyResult;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.aws.kms.crypto.KmsGenerateDataKeyOperation;
import com.nimbusds.jose.aws.kms.crypto.impl.models.CacheConfiguration;
import java.time.Duration;
import java.util.concurrent.ExecutionException;
import lombok.NonNull;

public class LoadingCachedKmsGenerateDataKeyOperation implements KmsGenerateDataKeyOperation {

    @NonNull
    private final KmsGenerateDataKeyOperation kmsGenerateDataKeyOperation;

    @NonNull
    private final LoadingCache<GenerateDataKeyRequest, GenerateDataKeyResult> dataKeyLoadingCache;

    public LoadingCachedKmsGenerateDataKeyOperation(@NonNull final KmsGenerateDataKeyOperation kmsGenerateDataKeyOperation) {
        this(kmsGenerateDataKeyOperation, CacheConfiguration.builder()
                .expireAfterWrite(Duration.ofMinutes(30))
                .maximumSize(100)
                .build());
    }

    public LoadingCachedKmsGenerateDataKeyOperation(
            @NonNull final KmsGenerateDataKeyOperation kmsGenerateDataKeyOperation,
            @NonNull final CacheConfiguration cacheConfiguration) {
        this.kmsGenerateDataKeyOperation = kmsGenerateDataKeyOperation;
        this.dataKeyLoadingCache = CacheBuilder.newBuilder()
                .expireAfterWrite(cacheConfiguration.getExpireAfterWrite())
                .maximumSize(cacheConfiguration.getMaximumSize())
                .build(new CacheLoader<GenerateDataKeyRequest, GenerateDataKeyResult>() {
                    @Override
                    public GenerateDataKeyResult load(@NonNull final GenerateDataKeyRequest request) throws Exception {
                        return kmsGenerateDataKeyOperation.generateDataKey(request);
                    }
                });
    }

    @Override
    public GenerateDataKeyResult generateDataKey(@NonNull final GenerateDataKeyRequest request) throws JOSEException {
        try {
            return dataKeyLoadingCache.get(request);
        } catch (ExecutionException e) {
            throw new JOSEException("Error occurred while calling `get()` on `dataKeyLoadingCache`.", e);
        }
    }
}
