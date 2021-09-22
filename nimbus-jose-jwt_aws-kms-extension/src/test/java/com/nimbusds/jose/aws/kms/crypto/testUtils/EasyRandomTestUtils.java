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
