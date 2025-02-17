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

package com.nimbusds.jose.aws.kms.scripts;

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.aws.kms.crypto.KmsSymmetricDecrypter;
import lombok.var;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import software.amazon.awssdk.services.kms.KmsClient;

import static com.nimbusds.jose.aws.kms.scripts.ScriptConstants.LINE_SEPARATOR;
import static java.lang.System.out;

/**
 * Script to decrypt a text payload using a KMS Symmetric CMK and generate a JWE token.
 */
public class KmsSymmetricJweCompactDecrypterScript {

    /**
     * Command to invoke this script.
     */
    private static final String COMMAND = "gradle kmsSymmetricJWEDecrypt";

    public static void main(String[] args) throws Exception {
        new KmsSymmetricJweCompactDecrypterScript().execute(args);
    }

    private void execute(String[] args) throws Exception {
        var options = buildOptions();
        var cmd = new DefaultParser().parse(options, args);
        if (cmd.hasOption(KmsSymmetricJweCompactDecrypterScriptOptionNames.HELP)) {
            out.println(LINE_SEPARATOR);
            new HelpFormatter().printHelp(COMMAND, options);
            out.println(LINE_SEPARATOR);
        } else if (
                !(cmd.hasOption(KmsSymmetricJweCompactDecrypterScriptOptionNames.JWE_TOKEN))) {
            out.printf("%1$s%2$s option is required. Use '%3$s' for details of this option.%1$s",
                    LINE_SEPARATOR, KmsSymmetricJweCompactDecrypterScriptOptionNames.JWE_TOKEN,
                    KmsSymmetricJweCompactDecrypterScriptOptionNames.HELP);
        } else {
            var jweObject = decrypt(cmd.getOptionValue(KmsSymmetricJweCompactDecrypterScriptOptionNames.JWE_TOKEN));

            out.printf("%1$sDECRYPTED TEXT :%1$s%2$s%1$s", LINE_SEPARATOR, jweObject.getPayload());
        }
    }

    private Options buildOptions() {
        var options = new Options();

        options.addOption(Option.builder()
                .longOpt(KmsSymmetricJweCompactDecrypterScriptOptionNames.HELP)
                .desc("Print this help message.")
                .build());
        options.addOption(Option.builder()
                .hasArg()
                .longOpt(KmsSymmetricJweCompactDecrypterScriptOptionNames.JWE_TOKEN)
                .desc("Serialized JWE token to decrypt.")
                .build());

        return options;
    }


//    @SuppressWarnings({"unchecked", "rawtypes"})
//    private Map<String, String> getEncryptionContext(JWEHeader header) {
//        return (Map) header.getCustomParam(KmsSymmetricCryptoProvider.ENCRYPTION_CONTEXT_HEADER);
//    }


    private JWEObject decrypt(String serializedJwe)
            throws Exception {

        var jweObject = JWEObject.parse(serializedJwe);
        var jweHeader = jweObject.getHeader();
        jweObject.decrypt(new KmsSymmetricDecrypter(
                KmsClient.create(),
                jweHeader.getKeyID()));

        return jweObject;
    }
}

/**
 * Option names for {@link KmsSymmetricJweCompactDecrypterScript}. Description of each option can be found where the
 * option is defined.
 */
final class KmsSymmetricJweCompactDecrypterScriptOptionNames {

    public static final String HELP = "help";
    public static final String JWE_TOKEN = "jweToken";

    private KmsSymmetricJweCompactDecrypterScriptOptionNames() {
    }
}
