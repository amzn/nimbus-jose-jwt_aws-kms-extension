package com.nimbusds.jose.aws.kms.scripts;

import static com.nimbusds.jose.aws.kms.scripts.ScriptConstants.LINE_SEPARATOR;
import static com.nimbusds.jose.aws.kms.scripts.ScriptConstants.MESSAGE_TYPE;
import static java.lang.System.out;

import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.MessageType;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.aws.kms.crypto.KmsAsymmetricRsaSsaVerifier;
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
    private static final String COMMAND = "gradle kmsSymmetricJWSVerify";


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
                    cmd.getOptionValue(KmsAsymmetricJwsCompactVerifierScriptOptionNames.JWS_TOKEN));

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

        return options;
    }

    private boolean verify(String serializedJws)
            throws Exception {

        var jwsObject = JWSObject.parse(serializedJws);

        return jwsObject.verify(new KmsAsymmetricRsaSsaVerifier(
                AWSKMSClientBuilder.defaultClient(),
                jwsObject.getHeader().getKeyID(),
                MessageType.fromValue(jwsObject.getHeader().getCustomParam(MESSAGE_TYPE).toString())));
    }
}

final class KmsAsymmetricJwsCompactVerifierScriptOptionNames {

    public static final String HELP = "help";
    public static final String JWS_TOKEN = "jwsToken";

    private KmsAsymmetricJwsCompactVerifierScriptOptionNames() {
    }
}
