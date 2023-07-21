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
import static com.nimbusds.jose.aws.kms.scripts.ScriptConstants.MESSAGE_TYPE;
import static java.lang.System.out;

import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.MessageType;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.aws.kms.crypto.KmsAsymmetricVerifier;
import java.util.Arrays;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.var;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;

/**
 * Script to verify a text payload using a KMS Symmetric CMK and generate a JWE token.
 */
public class KmsAsymmetricJwsCompactVerifierScript {

    /**
     * Command to invoke this script.
     */
    private static final String COMMAND = "gradle kmsAsymmetricJWSVerify";


    public static void main(String[] args) throws Exception {
        new KmsAsymmetricJwsCompactVerifierScript().execute(args);
    }

    private void execute(String[] args) throws Exception {
        var options = buildOptions();
        var cmd = new DefaultParser().parse(options, args);
        if (cmd.hasOption(KmsAsymmetricJwsCompactVerifierScriptOptionNames.HELP)) {
            out.println(LINE_SEPARATOR);
            new HelpFormatter().printHelp(COMMAND, options);
            out.println(LINE_SEPARATOR);
        } else if (
                !(cmd.hasOption(KmsAsymmetricJwsCompactVerifierScriptOptionNames.JWS_TOKEN))) {
            out.printf("%1$s%2$s option is required. Use '%3$s' for details of this option.%1$s",
                    LINE_SEPARATOR, KmsAsymmetricJwsCompactVerifierScriptOptionNames.JWS_TOKEN,
                    KmsAsymmetricJwsCompactVerifierScriptOptionNames.HELP);
        } else {
            var verificationResult = verify(
                    cmd.getOptionValue(KmsAsymmetricJwsCompactVerifierScriptOptionNames.JWS_TOKEN),
                    cmd.getOptionValue(KmsAsymmetricJwsCompactVerifierScriptOptionNames.MESSAGE_TYPE),
                    cmd.getOptionValue(KmsAsymmetricJwsCompactVerifierScriptOptionNames.DEFERRED_CRITICAL_HEADERS));

            out.printf("%1$sVERIFYCATION STATUS :%1$s%2$s%1$s", LINE_SEPARATOR,
                    verificationResult ? "Verified" : "Not Verified");
        }
    }

    private Options buildOptions() {
        var options = new Options();

        options.addOption(Option.builder()
                .longOpt(KmsAsymmetricJwsCompactVerifierScriptOptionNames.HELP)
                .desc("Print this help message.")
                .build());
        options.addOption(Option.builder()
                .hasArg()
                .longOpt(KmsAsymmetricJwsCompactVerifierScriptOptionNames.JWS_TOKEN)
                .desc("Serialized JWS Token to Verify")
                .build());
        options.addOption(Option.builder()
                .hasArg()
                .longOpt(KmsAsymmetricJwsCompactVerifierScriptOptionNames.MESSAGE_TYPE)
                .desc("Type Of message can be Digest or raw" +
                        "https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html#API_Sign_RequestSyntax")
                .build());
        options.addOption(Option.builder()
                .hasArg()
                .longOpt(KmsAsymmetricJwsCompactVerifierScriptOptionNames.DEFERRED_CRITICAL_HEADERS)
                .desc("Comma separated critical headers which needs to be deferred from verification.")
                .build());

        return options;
    }

    private boolean verify(final String serializedJws, final String messageTypeString,
                           final String defCritHeadersString)
            throws Exception {

        var jwsObject = JWSObject.parse(serializedJws);

        final var messageType = MessageType.fromValue(
                Objects.nonNull(messageTypeString) ?
                        messageTypeString : jwsObject.getHeader().getCustomParam(MESSAGE_TYPE).toString());

        Set<String> defCritHeaders = null;
        if (Objects.nonNull(defCritHeadersString)) {
            defCritHeaders = Arrays.stream(defCritHeadersString.split(","))
                    .map(String::trim)
                    .collect(Collectors.toSet());
        }

        return jwsObject.verify(
                Objects.nonNull(defCritHeaders) ?
                        new KmsAsymmetricVerifier(
                                AWSKMSClientBuilder.defaultClient(), jwsObject.getHeader().getKeyID(), messageType,
                                defCritHeaders)
                        : new KmsAsymmetricVerifier(
                                AWSKMSClientBuilder.defaultClient(), jwsObject.getHeader().getKeyID(), messageType));
    }
}

final class KmsAsymmetricJwsCompactVerifierScriptOptionNames {

    public static final String HELP = "help";
    public static final String JWS_TOKEN = "jwsToken";

    public static final String MESSAGE_TYPE = "messageType";

    public static final String DEFERRED_CRITICAL_HEADERS = "defCritHeaders";

    private KmsAsymmetricJwsCompactVerifierScriptOptionNames() {
    }
}
