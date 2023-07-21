# nimbus-jose-jwt_aws-kms-extension

This library package is an **extension of [nimbus-jose-jwt](https://connect2id.com/products/nimbus-jose-jwt)** library.
It is compatible with version 9.+ of nimbus-jose-jwt. It provides JWE based encrypters/decrypters and JWS based
signers/verifiers for doing operations with cryptographic keys stores in AWS KMS. This library requires Java 8 or above.

# Usage

In the current version following encryption and signing operations are supported:

1. Symmetric encryption (AES based).
    1. Classes: `com.nimbusds.jose.aws.kms.crypto.KmsSymmetricEncrypter`
       and `com.nimbusds.jose.aws.kms.crypto.KmsSymmetricDecrypter`
2. Asymmetric signing (RSA or ECDSA based).
    1. Classes: `com.nimbusds.jose.aws.kms.crypto.KmsAsymmetricSigner`
       and `com.nimbusds.jose.aws.kms.crypto.KmsAsymmetricVerifier`

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
    final var jwsSigner = new KmsAsymmetricSigner(
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

This library is available on [Maven Central](https://search.maven.org/artifact/software.amazon.lynx/nimbus-jose-jwt_aws-kms-extension).
Following are the installation details.

## Apache Maven
```xml
<dependency>
    <groupId>software.amazon.lynx</groupId>
    <artifactId>nimbus-jose-jwt_aws-kms-extension</artifactId>
    <version>1.0.0</version>
</dependency>
```

## Gradle Groovy DSL
```groovy
repositories {
    mavenCentral()
}

dependencies {
    implementation "software.amazon.lynx:nimbus-jose-jwt_aws-kms-extension:1.0.0"
}
```

# Scripts

There are various scripts included in this package, which you can use to perform various encryption/signing operations.
You can find Gradle tasks and available options of these scripts in `scripts.gradle` file.

# Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

# License

This project is licensed under the Apache-2.0 License.
