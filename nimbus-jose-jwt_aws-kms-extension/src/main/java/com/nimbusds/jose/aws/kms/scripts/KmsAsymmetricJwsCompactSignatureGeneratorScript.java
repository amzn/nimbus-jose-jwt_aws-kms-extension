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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.aws.kms.crypto.KmsAsymmetricSigner;
import lombok.var;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.MessageType;

import static com.nimbusds.jose.aws.kms.scripts.ScriptConstants.LINE_SEPARATOR;
import static com.nimbusds.jose.aws.kms.scripts.ScriptConstants.MESSAGE_TYPE;
import static java.lang.System.out;

/**
 * Script to generate signature for a text payload using a KMS Asymmetric CMK and generate a JWS token.
 */
public class KmsAsymmetricJwsCompactSignatureGeneratorScript {

    /**
     * Command to invoke this script.
     */
    private static final String COMMAND = "gradle kmsAsymmetricJWSSign";

    public static void main(String[] args) throws Exception {
        new KmsAsymmetricJwsCompactSignatureGeneratorScript().execute(args);
    }

    private void execute(String[] args) throws Exception {
        var options = buildOptions();
        var cmd = new DefaultParser().parse(options, args);

        if (cmd.hasOption(KmsAsymmetricJwsCompactSignatureGeneratorScriptOptionNames.HELP)) {
            out.println(LINE_SEPARATOR);
            new HelpFormatter().printHelp(COMMAND, options);
            out.println(LINE_SEPARATOR);
        } else if (!(cmd.hasOption(KmsAsymmetricJwsCompactSignatureGeneratorScriptOptionNames.ALG)
                && cmd.hasOption(KmsAsymmetricJwsCompactSignatureGeneratorScriptOptionNames.KID)
                && cmd.hasOption(KmsAsymmetricJwsCompactSignatureGeneratorScriptOptionNames.PAYLOAD)
                && cmd.hasOption(KmsAsymmetricJwsCompactSignatureGeneratorScriptOptionNames.MESSAGE_TYPE))) {
            out.printf("%1$s%2$s, %3$s, %4$s, %5$s options are required. "
                            + "Use '--%6$s' for details of these options.%1$s",
                    LINE_SEPARATOR, KmsAsymmetricJwsCompactSignatureGeneratorScriptOptionNames.ALG,
                    KmsAsymmetricJwsCompactSignatureGeneratorScriptOptionNames.KID,
                    KmsAsymmetricJwsCompactSignatureGeneratorScriptOptionNames.PAYLOAD,
                    KmsAsymmetricJwsCompactSignatureGeneratorScriptOptionNames.MESSAGE_TYPE,
                    KmsAsymmetricJwsCompactSignatureGeneratorScriptOptionNames.HELP);
        } else {
            var jwsObject = sign(
                    JWSAlgorithm
                            .parse(cmd.getOptionValue(KmsAsymmetricJwsCompactSignatureGeneratorScriptOptionNames.ALG)),
                    cmd.getOptionValue(KmsAsymmetricJwsCompactSignatureGeneratorScriptOptionNames.KID),
                    cmd.getOptionValue(KmsAsymmetricJwsCompactSignatureGeneratorScriptOptionNames.PAYLOAD),
                    cmd.getOptionValue(KmsAsymmetricJwsCompactSignatureGeneratorScriptOptionNames.MESSAGE_TYPE));

            out.printf("%1$sJWS Token:%1$s%2$s%1$s", LINE_SEPARATOR, jwsObject.serialize());
        }
    }

    private Options buildOptions() {
        var options = new Options();

        options.addOption(Option.builder()
                .longOpt(KmsAsymmetricJwsCompactSignatureGeneratorScriptOptionNames.HELP)
                .desc("Print this help message.")
                .build());
        options.addOption(Option.builder()
                .hasArg()
                .longOpt(KmsAsymmetricJwsCompactSignatureGeneratorScriptOptionNames.ALG)
                .desc("JWS signature generation algorithm")
                .build());
        options.addOption(Option.builder()
                .hasArg()
                .longOpt(KmsAsymmetricJwsCompactSignatureGeneratorScriptOptionNames.KID)
                .desc("Id of the key, which should used for signature generation."
                        + " Pass a KMS CMK ARN or alias ARN."
                        + " Note: You'll have to configure credentials of an IAM user in the default profile,"
                        + " who as access to the provided CMK."
                        + " Follow these instruction to configure user credentials:"
                        + " https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html"
                        + "#cli-configure-files-where")
                .build());
        options.addOption(Option.builder()
                .hasArg()
                .longOpt(KmsAsymmetricJwsCompactSignatureGeneratorScriptOptionNames.MESSAGE_TYPE)
                .desc("Type Of message can be Digest or raw" +
                        "https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html#API_Sign_RequestSyntax")
                .build());
        options.addOption(Option.builder()
                .hasArg()
                .longOpt(KmsAsymmetricJwsCompactSignatureGeneratorScriptOptionNames.PAYLOAD)
                .desc("Payload to for signature generation.")
                .build());

        return options;
    }

    private JWSObject sign(final JWSAlgorithm alg, final String kid, final String payload, final String messageType)
            throws Exception {
        final var jwsSigner = new KmsAsymmetricSigner(
                KmsClient.create(),
                kid,
                MessageType.fromValue(messageType));
        final var jwsHeader = new JWSHeader.Builder(alg)
                .keyID(kid)
                .customParam(MESSAGE_TYPE, messageType)
                .build();
        final var jwsObject = new JWSObject(jwsHeader, new Payload(payload));
        jwsObject.sign(jwsSigner);
        return jwsObject;
    }
}

/**
 * Option names for {@link KmsAsymmetricJwsCompactSignatureGeneratorScript}. Description of each option can be found
 * where the option is defined.
 */
final class KmsAsymmetricJwsCompactSignatureGeneratorScriptOptionNames {

    public static final String HELP = "help";
    public static final String PAYLOAD = "payload";
    public static final String MESSAGE_TYPE = "messageType";
    // For following options, we are using the terminology used in JWS spec. Ref: https://tools.ietf.org/html/rfc7516
    public static final String ALG = "alg";
    public static final String KID = "kid";

    private KmsAsymmetricJwsCompactSignatureGeneratorScriptOptionNames() {
    }
}
