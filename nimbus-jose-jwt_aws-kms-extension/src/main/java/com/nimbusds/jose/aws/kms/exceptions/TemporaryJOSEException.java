package com.nimbusds.jose.aws.kms.exceptions;

import com.nimbusds.jose.JOSEException;
import lombok.NonNull;

public class TemporaryJOSEException extends JOSEException {

    public TemporaryJOSEException(@NonNull final String message) {
        super(message);
    }

    public TemporaryJOSEException(@NonNull final String message, @NonNull final Throwable cause) {
        super(message, cause);
    }
}
