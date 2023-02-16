package com.nimbusds.jose.aws.kms.crypto.impl.models;

import java.time.Duration;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;

@Builder
@Getter
@EqualsAndHashCode
public class CacheConfiguration {
    private Duration expireAfterWrite;
    private long maximumSize;
}
