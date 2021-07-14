package com.nimbusds.jose.aws.kms.crypto;

import com.amazonaws.services.kms.AWSKMS;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWECryptoParts;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.KeyLengthException;
import lombok.NonNull;

public class KmsSymmetricEncrypter extends KmsSymmetricCryptoProvider implements JWEEncrypter {

    @NonNull
    private final AWSKMS kms;

    /**
     * Creates a new AES encrypter.
     *
     * @param kek The Key Encryption Key. Must be 128 bits (16 bytes), 192 bits (24 bytes) or 256 bits (32 bytes). Must
     *            not be {@code null}.
     * @param kms
     * @throws KeyLengthException If the KEK length is invalid.
     */
    public KmsSymmetricEncrypter(final String kek, final AWSKMS kms)
            throws KeyLengthException {
        super(kek);
        this.kms = kms;
    }

    @Override
    public JWECryptoParts encrypt(final JWEHeader header, final byte[] clearText)
            throws JOSEException {

//        final JWEAlgorithm alg = header.getAlgorithm();
//
//
//        if (!alg.equals(JWEAlgorithm.parse(EncryptionAlgorithmSpec.SYMMETRIC_DEFAULT.toString()))) {
//            throw new JOSEException(AlgorithmSupportMessage.unsupportedJWEAlgorithm(alg, SUPPORTED_ALGORITHMS));
//        }
//
//        final JWEHeader updatedHeader; // We need to work on the header
//        final Base64URL encryptedKey; // The second JWE part
//
//        // Generate and encrypt the CEK according to the enc method
//        final EncryptionMethod enc = header.getEncryptionMethod();
//        // data gene
//
//        final SecretKey cek = ContentCryptoProvider.generateCEK(enc, getJCAContext().getSecureRandom());

//        if (KmsSymmetricEncrypter.AlgFamily.AESKW.equals(algFamily)) {
//
//            encryptedKey = Base64URL.encode(AESKW.wrapCEK(cek, getKey(), getJCAContext().getKeyEncryptionProvider()));
//            updatedHeader = header; // simply copy ref
//
//        } else {
//            // This should never happen
//            throw new JOSEException("Unexpected JWE algorithm: " + alg);
//        }
        return null;
    }
//        return ContentCryptoProvider.encrypt(updatedHeader, clearText, cek, encryptedKey, getJCAContext());
//    }
//
//    private GenerateDataKeyResult generateDataKey(){
//        try {
//            return kms.generateDataKey(buildGenerateDataKeyRequest());
//        } catch (NotFoundException | DisabledException | InvalidKeyUsageException e) {
//            throw new PartnerGatewayConfigurationException(
//                    String.format(
//                            "An error was thrown from KMS due to invalid config. Config: %s",
//                            config),
//                    e);
//        } catch (KeyUnavailableException | DependencyTimeoutException | InvalidGrantTokenException
//                | KMSInternalException | KMSInvalidStateException e) {
//            throw new PartnerGatewayDependencyException("A temporary error was thrown from KMS.", e);
//        }
//    }

    }
