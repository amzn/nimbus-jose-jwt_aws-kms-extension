# nimbus-jose-jwt_aws-kms-extension

This library package is an **extension of [nimbus-jose-jwt](https://connect2id.com/products/nimbus-jose-jwt)** library.
It is compatible with version 9.+ of nimbus-jose-jwt. It provides JWE based encrypters/decrypters and JWS based
signers/verifiers for doing operations with cryptographic keys stores in AWS KMS. This library requires Java 8 or above.

# Usage

In the current version following encryption and signing operations are supported:

1. Symmetric encryption (AES based).
    1. Classes: `com.nimbusds.jose.aws.kms.crypto.KmsSymmetricEncrypter`
       and `com.nimbusds.jose.aws.kms.crypto.KmsSymmetricDecrypter`
2. RSA-SSA based signing.
    1. Classes: `com.nimbusds.jose.aws.kms.crypto.KmsAsymmetricRSASSASigner`
       and `com.nimbusds.jose.aws.kms.crypto.KmsAsymmetricRSASSAVerifier`

Above classes should be used in the same way any encryption or signing class, which is directly provided by
nimbus-jose-jwt, is used.

## Encryption Example (Java 11)

```jshelllanguage
    final var jweEncrypter = new KmsSymmetricEncrypter(AWSKMSClientBuilder.defaultClient(), kid);

    final var jweHeader = new JWEHeader.Builder(alg, enc).keyID(kid).build();

    final var jweObject = new JWEObject(jweHeader, new Payload(payload));

    jweObject.encrypt(jweEncrypter);
```

## Signing Example (Java 11)

```jshelllanguage
    final var jwsSigner = new KmsAsymmetricRSASSASigner(
        AWSKMSClientBuilder.defaultClient(),
        kid,
        MessageType.fromValue(messageType));

    final var jwsHeader = new JWSHeader.Builder(alg)
            .keyID(kid)
            .customParam(MESSAGE_TYPE, messageType)
            .build();

    final var jwsObject = new JWSObject(jwsHeader, new Payload(payload));

    jwsObject.sign(jwsSigner);
```

# Installation

For now, you can directly depend upon the git branch 'v-1.0.0'. We'll publish this package on MavenCentral soon.

# Scripts

There are various scripts included in this package, which you can use to perform various encryption/signing operations.
You can find Gradle tasks and available options of these scripts in `scripts.gradle` file.

# Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

# License

This project is licensed under the Apache-2.0 License.
