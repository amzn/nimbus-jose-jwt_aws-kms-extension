package com.nimbusds.jose.aws.kms.crypto.testUtils;

import java.nio.ByteBuffer;
import lombok.experimental.UtilityClass;
import lombok.var;
import org.jeasy.random.EasyRandom;
import org.jeasy.random.EasyRandomParameters;

@UtilityClass
public class EasyRandomTestUtils {

    public EasyRandom getEasyRandomWithByteBufferSupport() {
        return new EasyRandom(new EasyRandomParameters()
                .randomize(ByteBuffer.class, () -> {
                    final var random = new EasyRandom();
                    final var byteBuffer = ByteBuffer.allocate(random.nextInt(512));
                    random.nextBytes(byteBuffer.array());
                    return byteBuffer;
                }));
    }
}
