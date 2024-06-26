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

import static com.nimbusds.jose.aws.kms.scripts.ScriptConstants.LINE_SEPARATOR;
import static java.lang.System.out;

import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.aws.kms.crypto.KmsDefaultDecrypter;
import lombok.var;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;

/**
 * Script to decrypt a text payload using a KMS key and generate a JWE token.
 */
public class KmsDefaultJweCompactDecrypterScript {

    /**
     * Command to invoke this script.
     */
    private static final String COMMAND = "gradle kmsDefaultJWEDecrypt";

    public static void main(String[] args) throws Exception {
        new KmsDefaultJweCompactDecrypterScript().execute(args);
    }

    private void execute(String[] args) throws Exception {
        var options = buildOptions();
        var cmd = new DefaultParser().parse(options, args);

        if (cmd.hasOption(KmsDefaultJweCompactDecrypterScriptOptionNames.HELP)) {
            out.println(LINE_SEPARATOR);
            new HelpFormatter().printHelp(COMMAND, options);
            out.println(LINE_SEPARATOR);
        } else if (
                !(cmd.hasOption(KmsDefaultJweCompactDecrypterScriptOptionNames.JWE_TOKEN))) {
            out.printf("%1$s%2$s option is required. Use '%3$s' for details of this option.%1$s",
                    LINE_SEPARATOR, KmsDefaultJweCompactDecrypterScriptOptionNames.JWE_TOKEN,
                    KmsDefaultJweCompactDecrypterScriptOptionNames.HELP);
        } else {
            var jweObject = decrypt(cmd.getOptionValue(KmsDefaultJweCompactDecrypterScriptOptionNames.JWE_TOKEN));
            out.printf("%1$sDECRYPTED TEXT :%1$s%2$s%1$s", LINE_SEPARATOR, jweObject.getPayload());
        }
    }

    private Options buildOptions() {
        var options = new Options();

        options.addOption(Option.builder()
                .longOpt(KmsDefaultJweCompactDecrypterScriptOptionNames.HELP)
                .desc("Print this help message.")
                .build());
        options.addOption(Option.builder()
                .hasArg()
                .longOpt(KmsDefaultJweCompactDecrypterScriptOptionNames.JWE_TOKEN)
                .desc("Serialized JWE token to decrypt.")
                .build());

        return options;
    }

    private JWEObject decrypt(String serializedJwe) throws Exception {

        var jweObject = JWEObject.parse(serializedJwe);
        var jweHeader = jweObject.getHeader();
        jweObject.decrypt(new KmsDefaultDecrypter(
                AWSKMSClientBuilder.defaultClient(),
                jweHeader.getKeyID()));

        return jweObject;
    }

}

/**
 * Option names for {@link KmsDefaultJweCompactDecrypterScript}. Description of each option can be found where the
 * option is defined.
 */
final class KmsDefaultJweCompactDecrypterScriptOptionNames {

    private KmsDefaultJweCompactDecrypterScriptOptionNames() {
    }

    public static final String HELP = "help";
    public static final String JWE_TOKEN = "jweToken";
}

