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
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.aws.kms.crypto.KmsDefaultEncrypter;
import lombok.var;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;

/**
 * Script to encrypt a text payload using a KMS key and generate a JWE token.
 */
public class KmsDefaultJweCompactEncrypterScript {

    /**
     * Command to invoke this script.
     */
    private static final String COMMAND = "gradle kmsDefaultJWEEncrypt";

    public static void main(String[] args) throws Exception {
        new KmsDefaultJweCompactEncrypterScript().execute(args);
    }

    private void execute(String[] args) throws Exception {
        var options = buildOptions();
        var cmd = new DefaultParser().parse(options, args);

        if (cmd.hasOption(KmsDefaultJweCompactEncrypterScriptOptionNames.HELP)) {

            out.println(LINE_SEPARATOR);
            new HelpFormatter().printHelp(COMMAND, options);
            out.println(LINE_SEPARATOR);
        } else if (
                !(cmd.hasOption(KmsDefaultJweCompactEncrypterScriptOptionNames.ALG) && cmd.hasOption(
                        KmsDefaultJweCompactEncrypterScriptOptionNames.ENC) && cmd.hasOption(
                        KmsDefaultJweCompactEncrypterScriptOptionNames.KID) && cmd.hasOption(
                        KmsDefaultJweCompactEncrypterScriptOptionNames.PAYLOAD))) {

            out.printf("%1$s%2$s, %3$s, %4$s and %5$s options are required. "
                            + "Use '%6$s' for details of these options.%1$s",
                    LINE_SEPARATOR, KmsDefaultJweCompactEncrypterScriptOptionNames.ALG,
                    KmsDefaultJweCompactEncrypterScriptOptionNames.ENC,
                    KmsDefaultJweCompactEncrypterScriptOptionNames.KID,
                    KmsDefaultJweCompactEncrypterScriptOptionNames.PAYLOAD,
                    KmsDefaultJweCompactEncrypterScriptOptionNames.HELP);
        } else {

            var jweObject = encrypt(
                    JWEAlgorithm.parse(cmd.getOptionValue(KmsDefaultJweCompactEncrypterScriptOptionNames.ALG)),
                    EncryptionMethod.parse(cmd.getOptionValue(KmsDefaultJweCompactEncrypterScriptOptionNames.ENC)),
                    cmd.getOptionValue(KmsDefaultJweCompactEncrypterScriptOptionNames.KID),
                    cmd.getOptionValue(KmsDefaultJweCompactEncrypterScriptOptionNames.PAYLOAD));
            out.printf("%1$sJWE Token:%1$s%2$s%1$s", LINE_SEPARATOR, jweObject.serialize());
        }
    }

    private Options buildOptions() {
        var options = new Options();

        options.addOption(Option.builder()
                .longOpt(KmsDefaultJweCompactEncrypterScriptOptionNames.HELP)
                .desc("Print this help message.")
                .build());
        options.addOption(Option.builder()
                .hasArg()
                .longOpt(KmsDefaultJweCompactEncrypterScriptOptionNames.ALG)
                .desc("CEK encryption algorithm")
                .build());
        options.addOption(Option.builder()
                .hasArg()
                .longOpt(KmsDefaultJweCompactEncrypterScriptOptionNames.ENC)
                .desc("Content encryption algorithm/method.")
                .build());
        options.addOption(Option.builder()
                .hasArg()
                .longOpt(KmsDefaultJweCompactEncrypterScriptOptionNames.KID)
                .desc("Id of the key, which should used for encrypting CEK."
                        + " Pass a KMS key ARN or alias ARN."
                        + " Note: You'll have to configure credentials of an IAM user in the default profile,"
                        + " who as access to the provided KMS key."
                        + " Follow these instruction to configure user credentials:"
                        + " https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html"
                        + "#cli-configure-files-where")
                .build());
        options.addOption(Option.builder()
                .longOpt(KmsDefaultJweCompactEncrypterScriptOptionNames.PAYLOAD).hasArg()
                .desc("Payload to encrypt.")
                .build());

        return options;
    }

    private JWEObject encrypt(
            final JWEAlgorithm alg, final EncryptionMethod enc, final String kid, final String payload)
            throws Exception {
        var jweEncrypter = new KmsDefaultEncrypter(AWSKMSClientBuilder.defaultClient(), kid);
        var jweObject = new JWEObject(new JWEHeader.Builder(alg, enc).keyID(kid).build(), new Payload(payload));
        jweObject.encrypt(jweEncrypter);
        return jweObject;
    }
}

/**
 * Option names for {@link KmsDefaultJweCompactEncrypterScript}. Description of each option can be found where the
 * option is defined.
 */
final class KmsDefaultJweCompactEncrypterScriptOptionNames {

    private KmsDefaultJweCompactEncrypterScriptOptionNames() {
    }

    public static final String HELP = "help";
    public static final String PAYLOAD = "payload";

    // For following options, we are using the terminology used in JWE spec. Ref: https://tools.ietf.org/html/rfc7516
    public static final String ALG = "alg";
    public static final String ENC = "enc";
    public static final String KID = "kid";
}
