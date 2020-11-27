# Java Cryptography Architecture Standard Algorithm Name Documentation for JDK 8

- Standard Names
  - [`AlgorithmParameterGenerator` Algorithms](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#AlgorithmParameterGenerator)
  - [`AlgorithmParameters` Algorithms](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#AlgorithmParameters)
  - [`CertificateFactory` Types](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#CertificateFactory)
  - [`CertPathBuilder` Algorithms](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#CertPathBuilder)
  - [CertPath Encodings](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#CertPathEncodings)
  - [`CertPathValidator` Algorithms](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#CertPathValidator)
  - [`CertStore` Types](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#CertStore)
  - [`Cipher` (Encryption) Algorithms](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Cipher)
  - [`Configuration` Types](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Configuration)
  - [Exemption Mechanisms](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Exemption)
  - [GSSAPI Mechanisms](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#GSSAPI)
  - [`KeyAgreement` Algorithms](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyAgreement)
  - [`KeyFactory` Algorithms](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyFactory)
  - [`KeyGenerator` Algorithms](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyGenerator)
  - [`KeyManagerFactory` Algorithms](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyManagerFactory)
  - [`KeyPairGenerator` Algorithms](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyPairGenerator)
  - [`KeyStore` Types](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyStore)
  - [`Mac` Algorithms](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Mac)
  - [`MessageDigest` Algorithms](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#MessageDigest)
  - [`Policy` Types](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Policy)
  - [`SaslClient` Mechanisms](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#SaslClient)
  - [`SaslServer` Mechanisms](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#SaslServer)
  - [`SecretKeyFactory` Algorithms](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#SecretKeyFactory)
  - [`SecureRandom` Number Generation (RNG) Algorithms](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#SecureRandom)
  - [Service Attributes](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Service)
  - [`Signature` Algorithms](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Signature)
  - [`SSLContext` Algorithms](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#SSLContext)
  - [`TrustManagerFactory` Algorithms](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#TrustManagerFactory)
  - [XML Signature (`XMLSignatureFactory`/`KeyInfoFactory`/`TransformService)` Mechanisms](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#XMLSignature)
  - [XML Signature Transform (`TransformService`) Algorithms](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#TransformService)
  - [JSSE Cipher Suite Names](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#ciphersuites)
  - [Additional JSSE Standard Names](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#jssenames)
- Algorithms
  - [Specification Template](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#spectemp)
  - [Algorithm Specifications](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#algspec)
- [Implementation Requirements](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#impl)

------

**Note:** The [Oracle Providers Documentation](https://docs.oracle.com/javase/8/docs/technotes/guides/security/SunProviders.html) contains specific provider and algorithm information.

------

## Standard Names

The Java SE Security API requires and uses a set of standard names for algorithms, certificate and keystore types.

Note that an SE implementation may support additional algorithms that are not defined in this specification. As a best practice, if an algorithm is defined in a subsequent version of this specification and an implementation of an earlier specification supports that algorithm, the implementation should use the standard name of the algorithm that is defined in the subsequent specification. Each SE implementation should also document the algorithms that it supports or adds support for in subsequent update releases. The algorithms may be documented in release notes or in a separate document such as the [JDK Security Providers](https://docs.oracle.com/javase/8/docs/technotes/guides/security/SunProviders.html) document.

In some cases naming conventions are given for forming names that are not explicitly listed, to facilitate name consistency across provider implementations. Items in angle brackets (such as `<digest>` and `<encryption>`) are placeholders to be replaced by a specific message digest, encryption algorithm, or other name.

------

**Note:** Standard names are not case-sensitive.

------

This document includes corresponding lists of standard names relevant to the following security subareas:

- [**Java PKI Programmer's Guide**](https://docs.oracle.com/javase/8/docs/technotes/guides/security/certpath/CertPathProgGuide.html)
- [**JSSE Reference Guide**](https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html)
- For standard name specifications, See [Algorithms](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#alg).
- [**Cryptography Architecture**](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html)
- [**Single Sign-on Using Kerberos in Java**](https://docs.oracle.com/javase/8/docs/technotes/guides/security/jgss/tutorials/index.html)
- [**The Java SASL API Programming and Deployment Guide**](https://docs.oracle.com/javase/8/docs/technotes/guides/security/sasl/sasl-refguide.html)
- [**The XML Digital Signature API Specification**](https://docs.oracle.com/javase/8/docs/technotes/guides/security/xmldsig/overview.html)

## `AlgorithmParameterGenerator` Algorithms

The algorithm names in this section can be specified when generating an instance of `AlgorithmParameterGenerator`.

| Algorithm Name | Description                                              |
| -------------- | -------------------------------------------------------- |
| DiffieHellman  | Parameters for use with the Diffie-Hellman algorithm.    |
| DSA            | Parameters for use with the Digital Signature Algorithm. |

## `AlgorithmParameters` Algorithms

The algorithm names in this section can be specified when generating an instance of `AlgorithmParameters`.

| Algorithm Name                 | Description                                                  |
| ------------------------------ | ------------------------------------------------------------ |
| AES                            | Parameters for use with the AES algorithm.                   |
| Blowfish                       | Parameters for use with the Blowfish algorithm.              |
| DES                            | Parameters for use with the DES algorithm.                   |
| DESede                         | Parameters for use with the DESede algorithm.                |
| DiffieHellman                  | Parameters for use with the DiffieHellman algorithm.         |
| DSA                            | Parameters for use with the Digital Signature Algorithm.     |
| OAEP                           | Parameters for use with the OAEP algorithm.                  |
| PBEWith<digest>And<encryption> | Parameters for use with the PBEWith<digest>And<encryption> algorithm. Examples: **PBEWithMD5AndDES**, and **PBEWithHmacSHA256AndAES_128**. |
| PBE                            | Parameters for use with the PBE algorithm. *This name should not be used, in preference to the more specific PBE-algorithm names previously listed.* |
| RC2                            | Parameters for use with the RC2 algorithm.                   |
| RSASSA-PSS                     | Parameters for use with the RSASSA-PSS signature algorithm.  |

## `CertificateFactory` Types

The type in this section can be specified when generating an instance of `CertificateFactory`.

| Type  | Description                                                  |
| ----- | ------------------------------------------------------------ |
| X.509 | The certificate type defined in X.509, also available via [RFC 5280](https://tools.ietf.org/html/rfc5280) |

## `CertPathBuilder` Algorithms

The algorithm in this section can be specified when generating an instance of `CertPathBuilder`.

| Algorithm Name | Description                                                  |
| -------------- | ------------------------------------------------------------ |
| PKIX           | The PKIX certification path validation algorithm as defined in the [ValidationAlgorithm service attribute](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Service). The output of `CertPathBuilder` instances implementing this algorithm is a certification path validated against the PKIX validation algorithm. |

## CertPath Encodings

The following encodings may be passed to the `getEncoded` method of `CertPath` or the `generateCertPath(InputStream inStream, String encoding)` method of `CertificateFactory`.

| Encoding | Description                                                  |
| -------- | ------------------------------------------------------------ |
| PKCS7    | A PKCS #7 SignedData object, with the only significant field being certificates. In particular, the signature and the contents are ignored. If no certificates are present, a zero-length `CertPath` is assumed. Warning: PKCS #7 does not maintain the order of certificates in a certification path. This means that if a `CertPath` is converted to PKCS #7 encoded bytes and then converted back, the order of the certificates may change, potentially rendering the `CertPath` invalid. Users should be aware of this behavior. See [PKCS #7: Cryptographic Message Syntax](https://tools.ietf.org/html/rfc2315) for details on PKCS7. |
| PkiPath  | An ASN.1 DER encoded sequence of certificates, defined as follows:`    PkiPath ::= SEQUENCE OF Certificate `Within the sequence, the order of certificates is such that the subject of the first certificate is the issuer of the second certificate, and so on. Each certificate in `PkiPath` shall be unique. No certificate may appear more than once in a value of `Certificate` in `PkiPath`. The `PkiPath` format is defined in defect report 279 against X.509 (2000) and is incorporated into Technical Corrigendum 1 (DTC 2) for the ITU-T Recommendation X.509 (2000). See [the ITU web site](https://www.itu.int/rec/T-REC-X.509/en) for details. |

## `CertPathValidator` Algorithms

The algorithm in this section can be specified when generating an instance of `CertPathValidator`.

| Algorithm Name | Description                                                  |
| -------------- | ------------------------------------------------------------ |
| PKIX           | The PKIX certification path validation algorithm as defined in the [ValidationAlgorithm service attribute](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Service). |

## `CertStore` Types

The type in this section can be specified when generating an instance of `CertStore`.

| Type       | Description                                                  |
| ---------- | ------------------------------------------------------------ |
| Collection | A `CertStore` implementation that retrieves certificates and CRLs from a `Collection`. This type of `CertStore` is particularly useful in applications where certificates or CRLs are received in a bag or some sort of attachment, such as with a signed email message or in an SSL negotiation. |
| LDAP       | A `CertStore` implementation that fetches certificates and CRLs from an LDAP directory using the schema defined in the [LDAPSchema service attribute](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Service). |



## `Cipher` (Encryption) Algorithms

### Cipher Algorithm Names

The following names can be specified as the *algorithm* component in a [transformation](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#trans) when requesting an instance of `Cipher`.

| Algorithm Name                                             | Description                                                  |
| ---------------------------------------------------------- | ------------------------------------------------------------ |
| AES                                                        | Advanced Encryption Standard as specified by NIST in [FIPS 197](https://csrc.nist.gov/publications/detail/fips/197/final). Also known as the Rijndael algorithm by Joan Daemen and Vincent Rijmen, AES is a 128-bit block cipher supporting keys of 128, 192, and 256 bits.To use the AES cipher with only one valid key size, use the format AES_<n>, where <n> can be 128, 192, or 256. |
| AESWrap                                                    | The AES key wrapping algorithm as described in [RFC 3394](https://tools.ietf.org/html/rfc3394).To use the AESWrap cipher with only one valid key size, use the format AESWrap_<n>, where <n> can be 128, 192, or 256. |
| ARCFOUR                                                    | A stream cipher believed to be fully interoperable with the RC4 cipher developed by Ron Rivest. For more information, see [A Stream Cipher Encryption Algorithm "Arcfour"](https://tools.ietf.org/id/draft-kaukonen-cipher-arcfour-03.txt), Internet Draft (expired). |
| Blowfish                                                   | The [Blowfish block cipher](https://www.schneier.com/blowfish.html) designed by Bruce Schneier. |
| DES                                                        | The Digital Encryption Standard as described in [FIPS PUB 46-3](https://csrc.nist.gov/publications/fips/fips46-3/fips46-3.pdf). |
| DESede                                                     | Triple DES Encryption (also known as DES-EDE, 3DES, or Triple-DES). Data is encrypted using the DES algorithm three separate times. It is first encrypted using the first subkey, then decrypted with the second subkey, and encrypted with the third subkey. |
| DESedeWrap                                                 | The DESede key wrapping algorithm as described in [RFC 3217](https://tools.ietf.org/html/rfc3217). |
| ECIES                                                      | Elliptic Curve Integrated Encryption Scheme                  |
| PBEWith<digest>And<encryption> PBEWith<prf>And<encryption> | The password-based encryption algorithm found in (PKCS5), using the specified message digest (<digest>) or pseudo-random function (<prf>) and encryption algorithm (<encryption>). Examples:**PBEWithMD5AndDES**: The password-based encryption algorithm as defined in *RSA Laboratories, "PKCS #5: Password-Based Encryption Standard*, version 1.5, Nov 1993. Note that this algorithm implies [*CBC*](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#cbcMode) as the cipher mode and [*PKCS5Padding*](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#pkcs5Pad) as the padding scheme and cannot be used with any other cipher modes or padding schemes.**PBEWithHmacSHA256AndAES_128**: The password-based encryption algorithm as defined in [PKCS #5: Password-Based Cryptography Specification, Version 2.1](https://tools.ietf.org/html/rfc8018). |
| RC2                                                        | Variable-key-size encryption algorithms developed by Ron Rivest for RSA Data Security, Inc. |
| RC4                                                        | Variable-key-size encryption algorithms developed by Ron Rivest for RSA Data Security, Inc. (See note prior for ARCFOUR.) |
| RC5                                                        | Variable-key-size encryption algorithms developed by Ron Rivest for RSA Data Security, Inc. |
| RSA                                                        | The RSA encryption algorithm as defined in [PKCS #1 v2.2](https://tools.ietf.org/html/rfc8017) |

### Cipher Algorithm Modes

The following names can be specified as the *mode* component in a [transformation](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#trans) when requesting an instance of `Cipher`.

| Algorithm Name | Description                                                  |
| -------------- | ------------------------------------------------------------ |
| NONE           | No mode.                                                     |
| CBC            | Cipher Block Chaining Mode, as defined in [FIPS PUB 81](https://csrc.nist.gov/publications/fips/fips81/fips81.htm). |
| CCM            | Counter/CBC Mode, as defined in [NIST Special Publication SP 800-38C: Recommendation for Block Cipher Modes of Operation: the CCM Mode for Authentication and Confidentiality](https://csrc.nist.gov/publications/detail/sp/800-38c/final). |
| CFB, CFBx      | Cipher Feedback Mode, as defined in [FIPS PUB 81](https://csrc.nist.gov/publications/fips/fips81/fips81.htm).  Using modes such as CFB and OFB, block ciphers can encrypt data in units smaller than the cipher's actual block size. When requesting such a mode, you may optionally specify the number of bits to be processed at a time by appending this number to the mode name as shown in the *"DES/CFB8/NoPadding"* and *"DES/OFB32/PKCS5Padding"* transformations. If no such number is specified, a provider-specific default is used. (For example, the SunJCE provider uses a default of 64 bits for DES.) Thus, block ciphers can be turned into byte-oriented stream ciphers by using an 8-bit mode such as CFB8 or OFB8. |
| CTR            | A simplification of OFB, Counter mode updates the input block as a counter. |
| CTS            | Cipher Text Stealing, as described in Bruce Schneier's book *Applied Cryptography-Second Edition*, John Wiley and Sons, 1996. |
| ECB            | Electronic Codebook Mode, as defined in [FIPS PUB 81](https://csrc.nist.gov/publications/fips/fips81/fips81.htm) (generally this mode should not be used for multiple blocks of data). |
| GCM            | Galois/Counter Mode, as defined in [NIST Special Publication SP 800-38D Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC](https://csrc.nist.gov/publications/detail/sp/800-38d/final). |
| OFB, OFBx      | Output Feedback Mode, as defined in [FIPS PUB 81](https://csrc.nist.gov/publications/fips/fips81/fips81.htm).  Using modes such as CFB and OFB, block ciphers can encrypt data in units smaller than the cipher's actual block size. When requesting such a mode, you may optionally specify the number of bits to be processed at a time by appending this number to the mode name as shown in the "*DES/CFB8/NoPadding*" and "*DES/OFB32/PKCS5Padding*" transformations. If no such number is specified, a provider-specific default is used. (For example, the SunJCE provider uses a default of 64 bits for DES.) Thus, block ciphers can be turned into byte-oriented stream ciphers by using an 8-bit mode such as CFB8 or OFB8. |
| PCBC           | Propagating Cipher Block Chaining, as defined by [Kerberos V4](https://web.mit.edu/kerberos/). |

### Cipher Algorithm Padding

The following names can be specified as the *padding* component in a [transformation](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#trans) when requesting an instance of `Cipher`.

| Algorithm Name                               | Description                                                  |
| -------------------------------------------- | ------------------------------------------------------------ |
| NoPadding                                    | No padding.                                                  |
| ISO10126Padding                              | This padding for block ciphers is described in [5.2 Block Encryption Algorithms](https://www.w3.org/TR/xmlenc-core/#sec-Alg-Block) in the W3C's "XML Encryption Syntax and Processing" document. |
| OAEPPadding, OAEPWith<digest>And<mgf>Padding | Optimal Asymmetric Encryption Padding scheme defined in PKCS #1, where <digest> should be replaced by the message digest and <mgf> by the mask generation function. Examples: **OAEPWithMD5AndMGF1Padding** and **OAEPWithSHA-512AndMGF1Padding**.  If `OAEPPadding` is used, `Cipher` objects are initialized with a `javax.crypto.spec.OAEPParameterSpec` object to supply values needed for OAEPPadding. |
| PKCS1Padding                                 | The padding scheme described in [PKCS #1 v2.2](https://tools.ietf.org/html/rfc8017), used with the RSA algorithm. |
| PKCS5Padding                                 | The padding scheme described in [PKCS #5: Password-Based Cryptography Specification, version 2.1](https://tools.ietf.org/html/rfc8018). |
| SSL3Padding                                  | The padding scheme defined in the SSL Protocol Version 3.0, November 18, 1996, section 5.2.3.2 (CBC block cipher):`    block-ciphered struct {        opaque content[SSLCompressed.length];        opaque MAC[CipherSpec.hash_size];        uint8 padding[            GenericBlockCipher.padding_length];        uint8 padding_length;    } GenericBlockCipher; `The size of an instance of a GenericBlockCipher must be a multiple of the block cipher's block length.  The padding length, which is always present, contributes to the padding, which implies that if:`    sizeof(content) + sizeof(MAC) % block_length = 0,  `padding has to be (block_length - 1) bytes long, because of the existence of `padding_length`.  This makes the padding scheme similar (but not quite) to PKCS5Padding, where the padding length is encoded in the padding (and ranges from 1 to block_length). With the SSL scheme, the sizeof(padding) is encoded in the always present `padding_length` and therefore ranges from 0 to block_length-1. |

## `Configuration` Types

The type in this section can be specified when generating an instance of `javax.security.auth.login.Configuration`.

| Type            | Description                                                  |
| --------------- | ------------------------------------------------------------ |
| JavaLoginConfig | The default Configuration implementation from the SUN provider, as described in the [ConfigFile class specification](https://docs.oracle.com/javase/8/docs/technotes/guides/security/jaas/tutorials/LoginConfigFile.html). This type accepts `java.security.URIParameter` as a valid `Configuration.Parameter` type. If this parameter is not specified, then the configuration information is loaded from the sources described in the ConfigFile class specification. If this parameter is specified, the configuration information is loaded solely from the specified URI. |



## Exemption Mechanisms

The following exemption mechanism names can be specified in the permission policy file that accompanies an application considered "exempt" from cryptographic restrictions.

| Algorithm Name | Description                                                  |
| -------------- | ------------------------------------------------------------ |
| KeyEscrow      | An encryption system with a backup decryption capability that allows authorized persons (users, officers of an organization, and government officials), under certain prescribed conditions, to decrypt ciphertext with the help of information supplied by one or more trusted parties who hold special data recovery keys. |
| KeyRecovery    | A method of obtaining the secret key used to lock encrypted data. One use is as a means of providing fail-safe access to a corporation's own encrypted information in times of disaster. |
| KeyWeakening   | A method in which a part of the key can be escrowed or recovered. |



## GSSAPI Mechanisms

The following mechanisms can be specified when using GSSAPI. Note that Object Identifiers (OIDs) are specified instead of names to be consistent with the GSSAPI standard.

| Mechanism OID        | Description                                                  |
| -------------------- | ------------------------------------------------------------ |
| 1.2.840.113554.1.2.2 | The Kerberos v5 GSS-API mechanism defined in [RFC 4121](https://tools.ietf.org/html/rfc4121). |
| 1.3.6.1.5.5.2        | The Simple and Protected GSS-API Negotiation (SPNEGO) mechanism defined in [RFC 4178](https://tools.ietf.org/html/rfc4178). |



## `KeyAgreement` Algorithms

The following algorithm names can be specified when requesting an instance of `KeyAgreement`.

| Algorithm Name | Description                                                  |
| -------------- | ------------------------------------------------------------ |
| DiffieHellman  | Diffie-Hellman Key Agreement as defined in *PKCS #3: Diffie-Hellman Key-Agreement Standard*, RSA Laboratories, version 1.4, November 1993. |
| ECDH           | Elliptic Curve Diffie-Hellman as defined in ANSI X9.63 and as described in [RFC 3278](https://tools.ietf.org/html/rfc3278): "Use of Elliptic Curve Cryptography (ECC) Algorithms in Cryptographic Message Syntax (CMS)." |
| ECMQV          | Elliptic Curve Menezes-Qu-Vanstone.                          |

## `KeyFactory` Algorithms

*(Except as noted, these classes create keys for which [`Key.getAlgorithm()`](https://docs.oracle.com/javase/8/docs/api/java/security/Key.html#getAlgorithm--) returns the standard algorithm name.)*

The algorithm names in this section can be specified when generating an instance of `KeyFactory`.

| Algorithm Name | Description                                                  |
| -------------- | ------------------------------------------------------------ |
| DiffieHellman  | Keys for the Diffie-Hellman KeyAgreement algorithm.Note: `key.getAlgorithm()` will return "DH" instead of "DiffieHellman". |
| DSA            | Keys for the Digital Signature Algorithm.                    |
| RSA            | Keys for the RSA algorithm (Signature/Cipher).               |
| RSASSA-PSS     | Keys for the RSASSA-PSS algorithm (Signature).               |
| EC             | Keys for the Elliptic Curve algorithm.                       |



## `KeyGenerator` Algorithms

The following algorithm names can be specified when requesting an instance of `KeyGenerator`.

| Algorithm Name                                       | Description                                                  |
| ---------------------------------------------------- | ------------------------------------------------------------ |
| AES                                                  | Key generator for use with the AES algorithm.                |
| ARCFOUR                                              | Key generator for use with the ARCFOUR (RC4) algorithm.      |
| Blowfish                                             | Key generator for use with the Blowfish algorithm.           |
| DES                                                  | Key generator for use with the DES algorithm.                |
| DESede                                               | Key generator for use with the DESede (triple-DES) algorithm. |
| HmacMD5                                              | Key generator for use with the HmacMD5 algorithm.            |
| HmacSHA1 HmacSHA224 HmacSHA256 HmacSHA384 HmacSHA512 | Keys generator for use with the various flavors of the HmacSHA algorithms. |
| RC2                                                  | Key generator for use with the RC2 algorithm.                |

## `KeyManagerFactory` Algorithms

The algorithm name in this section can be specified when generating an instance of `KeyManagerFactory`.

| Algorithm Name | Description                                                  |
| -------------- | ------------------------------------------------------------ |
| PKIX           | A factory for `X509ExtendedKeyManager`s that manage X.509 certificate-based key pairs for local side authentication according to the rules defined by the IETF PKIX working group in [RFC 5280](https://tools.ietf.org/html/rfc5280) or its successor. The `KeyManagerFactory` must support initialization using the class `javax.net.ssl.KeyStoreBuilderParameters`. |

## `KeyPairGenerator` Algorithms

*(Except as noted, these classes create keys for which [`Key.getAlgorithm()`](https://docs.oracle.com/javase/8/docs/api/java/security/Key.html#getAlgorithm--) returns the standard algorithm name.)*

The algorithm names in this section can be specified when generating an instance of `KeyPairGenerator`.

| Algorithm Name | Description                                                  |
| -------------- | ------------------------------------------------------------ |
| DiffieHellman  | Generates keypairs for the Diffie-Hellman KeyAgreement algorithm.Note: `key.getAlgorithm()` will return "DH" instead of "DiffieHellman". |
| DSA            | Generates keypairs for the Digital Signature Algorithm.      |
| RSA            | Generates keypairs for the RSA algorithm (Signature/Cipher). |
| RSASSA-PSS     | Generates keypairs for the RSASSA-PSS signature algorithm.   |
| EC             | Generates keypairs for the Elliptic Curve algorithm.         |



## `KeyStore` Types

The types in this section can be specified when generating an instance of `KeyStore`.

| Type   | Description                                                  |
| ------ | ------------------------------------------------------------ |
| jceks  | The [proprietary keystore](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#KeystoreImplementation) implementation provided by the SunJCE provider. |
| jks    | The [proprietary keystore](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#KeystoreImplementation) implementation provided by the SUN provider. |
| dks    | A domain keystore is a collection of keystores presented as a single logical keystore. It is specified by configuration data whose syntax is described in [DomainLoadStoreParameter](https://docs.oracle.com/javase/8/docs/api/java/security/DomainLoadStoreParameter.html). |
| pkcs11 | A keystore backed by a PKCS #11 token.                       |
| pkcs12 | The transfer syntax for personal identity information as defined in [PKCS #12: Personal Information Exchange Syntax v1.1](https://tools.ietf.org/html/rfc7292). |



## `Mac` Algorithms

The following algorithm names can be specified when requesting an instance of `Mac`.

| Algorithm Name                                       | Description                                                  |
| ---------------------------------------------------- | ------------------------------------------------------------ |
| HmacMD5                                              | The HMAC-MD5 keyed-hashing algorithm as defined in [RFC 2104](https://tools.ietf.org/html/rfc2104) "HMAC: Keyed-Hashing for Message Authentication" (February 1997). |
| HmacSHA1 HmacSHA224 HmacSHA256 HmacSHA384 HmacSHA512 | The HmacSHA* algorithms as defined in [RFC 2104](https://tools.ietf.org/html/rfc2104) "HMAC: Keyed-Hashing for Message Authentication" (February 1997) with `SHA-*` as the message digest algorithm. |
| PBEWith<mac>                                         | Mac for use with the [PKCS #5](https://tools.ietf.org/html/rfc8018) password-based message authentication standard, where <mac> is a Message Authentication Code algorithm name. Example: **PBEWithHmacSHA1**. |

## `MessageDigest` Algorithms

The algorithm names in this section can be specified when generating an instance of `MessageDigest`.

| Algorithm Name                                               | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| MD2                                                          | The MD2 message digest algorithm as defined in [RFC 1319](https://tools.ietf.org/html/rfc1319). |
| MD5                                                          | The MD5 message digest algorithm as defined in [RFC 1321](https://tools.ietf.org/html/rfc1321). |
| SHA-1 SHA-224 SHA-256 SHA-384 SHA-512 SHA-512/224 SHA-512/256 | Hash algorithms defined in the [FIPS PUB 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final).  Secure hash algorithms - SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 - for computing a condensed representation of electronic data (message). When a message of any length less than 264 bits (for SHA-1, SHA-224, and SHA-256) or less than 2128 (for SHA-384 and SHA-512) is input to a hash algorithm, the result is an output called a message digest. A message digest ranges in length from 160 to 512 bits, depending on the algorithm. |

## `Policy` Types

The type in this section can be specified when generating an instance of `Policy`.

| Type       | Description                                                  |
| ---------- | ------------------------------------------------------------ |
| JavaPolicy | The default Policy implementation from the SUN provider, as described in the [PolicyFile](https://docs.oracle.com/javase/8/docs/technotes/guides/security/PolicyFiles.html) guide. This type accepts `java.security.URIParameter` as a valid `Policy.Parameter` type. If this parameter is not specified, then the policy information is loaded from the sources described in the [Default Policy File Locations](https://docs.oracle.com/javase/8/docs/technotes/guides/security/PolicyFiles.html#DefaultLocs) section of the PolicyFile guide. If this parameter is specified, the policy information is loaded solely from the specified URI. |

## `SaslClient` Mechanisms

The mechanisms in this section can be specified when generating an instance of `SaslClient`.

| Mechanism  | Description                                                  |
| ---------- | ------------------------------------------------------------ |
| CRAM-MD5   | See [RFC 2195](https://tools.ietf.org/html/rfc2195). This mechanism supports a hashed user name/password authentication scheme. |
| DIGEST-MD5 | See [RFC 2831](https://tools.ietf.org/html/rfc2831). This mechanism defines how HTTP Digest Authentication can be used as a SASL mechanism. |
| EXTERNAL   | See [RFC 2222](https://tools.ietf.org/html/rfc2222). This mechanism obtains authentication information from an external channel (such as TLS or IPsec). |
| GSSAPI     | See [RFC 2222](https://tools.ietf.org/html/rfc2222). This mechanism uses the GSSAPI for obtaining authentication information. It supports Kerberos v5 authentication. |
| PLAIN      | See [RFC 2595](https://tools.ietf.org/html/rfc2595). This mechanism supports cleartext user name/password authentication. |

## `SaslServer` Mechanisms

The mechanisms in this section can be specified when generating an instance of `SaslServer`.

| Mechanism  | Description                                                  |
| ---------- | ------------------------------------------------------------ |
| CRAM-MD5   | See [RFC 2195](https://tools.ietf.org/html/rfc2195). This mechanism supports a hashed user name/password authentication scheme. |
| DIGEST-MD5 | See [RFC 2831](https://tools.ietf.org/html/rfc2831). This mechanism defines how HTTP Digest Authentication can be used as a SASL mechanism. |
| GSSAPI     | See [RFC 2222](https://tools.ietf.org/html/rfc2222). This mechanism uses the GSSAPI for obtaining authentication information. It supports Kerberos v5 authentication. |



## `SecretKeyFactory` Algorithms

The following algorithm names can be specified when requesting an instance of `SecretKeyFactory`.

| Algorithm Name                                               | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| AES                                                          | Constructs secret keys for use with the AES algorithm.       |
| ARCFOUR                                                      | Constructs secret keys for use with the ARCFOUR algorithm.   |
| DES                                                          | Constructs secrets keys for use with the DES algorithm.      |
| DESede                                                       | Constructs secrets keys for use with the DESede (Triple-DES) algorithm. |
| PBEWith*<digest>*And*<encryption>* PBEWith*<prf>*And*<encryption>* | Secret-key factory for use with PKCS5 password-based encryption, where *<digest>* is a message digest, *<prf>* is a pseudo-random function, and *<encryption>* is an encryption algorithm.Examples:PBEWithMD5AndDES (PKCS #5, 1.5),PBEWithHmacSHA256AndAES_128 (PKCS #5, 2.0)Note: These all use only the low order 8 bits of each password character. |
| PBKDF2With*<prf>*                                            | Password-based key-derivation algorithm found in [PKCS #5](https://tools.ietf.org/html/rfc8018) using the specified pseudo-random function (*<prf>*). Example: PBKDF2WithHmacSHA256. |

## `SecureRandom` Number Generation Algorithms

The algorithm name in this section can be specified when generating an instance of `SecureRandom`.

| Algorithm Name        | Description                                                  |
| --------------------- | ------------------------------------------------------------ |
| NativePRNG            | Obtains random numbers from the underlying native OS. No assertions are made as to the blocking nature of generating these numbers. |
| NativePRNGBlocking    | Obtains random numbers from the underlying native OS, blocking if necessary. For example, `/dev/random` on UNIX-like systems. |
| NativePRNGNonBlocking | Obtains random numbers from the underlying native OS, without blocking to prevent applications from excessive stalling. For example, `/dev/urandom` on UNIX-like systems. |
| PKCS11                | Obtains random numbers from the underlying installed and configured PKCS11 library. |
| SHA1PRNG              | The name of the pseudo-random number generation (PRNG) algorithm supplied by the SUN provider. This algorithm uses SHA-1 as the foundation of the PRNG. It computes the SHA-1 hash over a true-random seed value concatenated with a 64-bit counter which is incremented by 1 for each operation. From the 160-bit SHA-1 output, only 64 bits are used. |
| Windows-PRNG          | Obtains random numbers from the underlying Windows OS.       |

## Service Attributes

A cryptographic service is always associated with a particular algorithm or type. For example, a digital signature service is always associated with a particular algorithm (for example, DSA), and a `CertificateFactory` service is always associated with a particular certificate type (for example, X.509).

The attributes in this section are for cryptographic services. The service attributes can be used as filters for selecting providers.

Both the attribute name and value are case-insensitive.

| Attribute           | Description                                                  |
| ------------------- | ------------------------------------------------------------ |
| KeySize             | The maximum key size that the provider supports for the cryptographic service. |
| ImplementedIn       | Whether the implementation for the cryptographic service is done by software or hardware. The value of this attribute is "software" or "hardware". |
| ValidationAlgorithm | The name of the specification that defines the certification path validation algorithm that an implementation of `CertPathBuilder` or `CertPathValidator` supports. RFCs should be specified as "RFC#" (ex: "RFC3280") and Internet Drafts as the name of the draft (ex: "draft-ietf-pkix-rfc2560bis-01.txt"). Values for this attribute that are specified as selection criteria to the `Security.getProviders` method will be compared using the `String.equalsIgnoreCase` method. All PKIX implementations of `CertPathBuilder` and `CertPathValidator` should provide a value for this attribute. |
| LDAPSchema          | The name of the specification that defines the LDAP schema that an implementation of an LDAP `CertStore` uses to retrieve certificates and CRLs. The format and semantics of this attribute is the same as described for the ValidationAlgorithm attribute. All LDAP implementations of `CertStore` should provide a value for this attribute. |

For example:

```
   map.put("KeyPairGenerator.DSA",
            "sun.security.provider.DSAKeyPairGenerator");
        map.put("KeyPairGenerator.DSA KeySize", "1024");
        map.put("KeyPairGenerator.DSA ImplementedIn", "Software");
```



## `Signature` Algorithms

The algorithm names in this section can be specified when generating an instance of `Signature`.

| Algorithm Name                                               | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| NONEwithRSA                                                  | The RSA signature algorithm, which does not use a digesting algorithm (for example, MD5/SHA1) before performing the RSA operation. For more information about the RSA Signature algorithms, see [PKCS #1 v2.2](https://tools.ietf.org/html/rfc8017). |
| MD2withRSA MD5withRSA                                        | The MD2/MD5 with RSA Encryption signature algorithm, which uses the MD2/MD5 digest algorithm and RSA to create and verify RSA digital signatures as defined in [PKCS #1](https://tools.ietf.org/html/rfc8017). |
| SHA1withRSA SHA224withRSA SHA256withRSA SHA384withRSA SHA512withRSA SHA512/224withRSA SHA512/256withRSA | The signature algorithm with SHA-* and the RSA encryption algorithm as defined in the OSI Interoperability Workshop, using the padding conventions described in [PKCS #1](https://tools.ietf.org/html/rfc8017). |
| RSASSA-PSS                                                   | The signature algorithm that uses the RSASSA-PSS signature scheme as defined in [PKCS #1 v2.2](https://tools.ietf.org/html/rfc8017). Note that this signature algorithm needs parameters such as a digesting algorithm, salt length and MGF1 algorithm, to be supplied before performing the RSA operation. |
| NONEwithDSA                                                  | The Digital Signature Algorithm as defined in [FIPS PUB 186-4](https://csrc.nist.gov/publications/detail/fips/186/4/final). The data must be exactly 20 bytes in length. This algorithm is also known as rawDSA. |
| SHA1withDSA SHA224withDSA SHA256withDSA SHA384withDSA SHA512withDSA | The DSA signature algorithms that use these digest algorithms to create and verify digital signatures as defined in [FIPS PUB 186-4](https://csrc.nist.gov/publications/detail/fips/186/4/final). |
| NONEwithECDSA SHA1withECDSA SHA224withECDSA SHA256withECDSA SHA384withECDSA SHA512withECDSA *(ECDSA)* | The ECDSA signature algorithms as defined in ANSI X9.62.**Note:**"ECDSA" is an ambiguous name for the "SHA1withECDSA" algorithm and should not be used. The formal name "SHA1withECDSA" should be used instead. |
| <digest>with<encryption>                                     | Use this to form a name for a signature algorithm with a particular message digest (such as MD2 or MD5) and algorithm (such as RSA or DSA), just as was done for the explicitly defined standard names in this section (MD2withRSA, and so on).For the new signature schemes defined in [PKCS #1 v2.2](https://tools.ietf.org/html/rfc8017), for which the <digest>with<encryption> form is insufficient, **<digest>with<encryption>and<mgf>** can be used to form a name. Here, <mgf> should be replaced by a mask generation function such as MGF1. Example: **MD5withRSAandMGF1**. |

## `SSLContext` Algorithms

The algorithm names in this section can be specified when generating an instance of `SSLContext`.

| Algorithm Name | Description                                                  |
| -------------- | ------------------------------------------------------------ |
| SSL            | Supports some version of SSL; may support other versions     |
| SSLv2          | Supports SSL version 2 or later; may support other versions  |
| SSLv3          | Supports SSL version 3; may support other versions           |
| TLS            | Supports some version of TLS; may support other versions     |
| TLSv1          | Supports [RFC 2246: TLS version 1.0](https://tools.ietf.org/html/rfc2246) ; may support other versions |
| TLSv1.1        | Supports [RFC 4346: TLS version 1.1](https://tools.ietf.org/html/rfc4346) ; may support other versions |
| TLSv1.2        | Supports [RFC 5246: TLS version 1.2](https://tools.ietf.org/html/rfc5246) ; may support other versions |

## `TrustManagerFactory` Algorithms

The algorithm name in this section can be specified when generating an instance of `TrustManagerFactory`.

| Algorithm Name | Description                                                  |
| -------------- | ------------------------------------------------------------ |
| PKIX           | A factory for `X509ExtendedTrustManager` objects that validate certificate chains according to the rules defined by the IETF PKIX working group in [RFC 5280](https://tools.ietf.org/html/rfc5280), Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile, or its successor. The `TrustManagerFactory` must support initialization using the class `javax.net.ssl.CertPathTrustManagerParameters`. |



## XML Signature (`XMLSignatureFactory`/`KeyInfoFactory`/`TransformService`) Mechanisms

The mechanism in this section can be specified when generating an instance of `XMLSignatureFactory`, `KeyInfoFactory`, or `TransformService`. The mechanism identifies the XML processing mechanism that an implementation uses internally to parse and generate XML signature and KeyInfo structures. Also, note that each `TransformService` instance supports a specific transform algorithm in addition to a mechanism. The standard names for the transform algorithms are defined in the next section.

| Mechanism | Description                                                  |
| --------- | ------------------------------------------------------------ |
| DOM       | The Document Object Model. See [DOM Mechanism Requirements](https://docs.oracle.com/javase/8/docs/technotes/guides/security/xmldsig/overview.html#DOM_Mechanism_Requirements) for additional requirements for DOM implementations. |



## XML Signature Transform (`TransformService`) Algorithms

The algorithms in this section can be specified when generating an instance of `TransformService`. Note that URIs are specified instead of names to be consistent with the XML Signature standard. API constants have been defined for each of these URIs, and these are listed in parentheses after each URI in the table that follows.

| Algorithm URI                                                | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| http://www.w3.org/TR/2001/REC-xml-c14n-20010315 (`CanonicalizationMethod.INCLUSIVE`) | The [Canonical XML (without comments)](https://www.w3.org/TR/2001/REC-xml-c14n-20010315) canonicalization algorithm. |
| http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments (`CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS`) | The [Canonical XML with comments](https://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments) canonicalization algorithm. |
| http://www.w3.org/2001/10/xml-exc-c14n# (`CanonicalizationMethod.EXCLUSIVE`) | The [Exclusive Canonical XML (without comments)](https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/#) canonicalization algorithm. |
| http://www.w3.org/2001/10/xml-exc-c14n#WithComments (`CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS`) | The [Exclusive Canonical XML with comments](https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/#WithComments) canonicalization algorithm. |
| http://www.w3.org/2000/09/xmldsig#base64 (`Transform.BASE64`) | The [Base64](https://www.w3.org/TR/xmldsig-core/#sec-Base-64) transform algorithm. |
| http://www.w3.org/2000/09/xmldsig#enveloped-signature (`Transform.ENVELOPED`) | The [Enveloped Signature](https://www.w3.org/TR/xmldsig-core/#sec-EnvelopedSignature) transform algorithm. |
| http://www.w3.org/TR/1999/REC-xpath-19991116 (`Transform.XPATH`) | The [XPath](https://www.w3.org/TR/xmldsig-core/#sec-XPath) transform algorithm. |
| http://www.w3.org/2002/06/xmldsig-filter2 (`Transform.XPATH2`) | The [XPath Filter 2](https://www.w3.org/TR/2002/REC-xmldsig-filter2-20021108/) transform algorithm. |
| http://www.w3.org/TR/1999/REC-xslt-19991116 (`Transform.XSLT`) | The [XSLT](https://www.w3.org/TR/xmldsig-core/#sec-XSLT) transform algorithm. |

## JSSE Cipher Suite Names



The following list contains the standard JSSE cipher suite names. Over time, various groups have added additional cipher suites to the SSL/TLS namespace. Some JSSE cipher suite names were defined before TLSv1.0 was finalized, and were therefore given the `SSL_` prefix. The names mentioned in the TLS RFCs prefixed with `TLS_` are functionally equivalent to the JSSE cipher suites prefixed with `SSL_`.

- SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA
- SSL_DH_anon_EXPORT_WITH_RC4_40_MD5
- SSL_DH_anon_WITH_3DES_EDE_CBC_SHA
- TLS_DH_anon_WITH_AES_128_CBC_SHA
- TLS_DH_anon_WITH_AES_128_CBC_SHA256
- TLS_DH_anon_WITH_AES_128_GCM_SHA256
- TLS_DH_anon_WITH_AES_256_CBC_SHA
- TLS_DH_anon_WITH_AES_256_CBC_SHA256
- TLS_DH_anon_WITH_AES_256_GCM_SHA384
- TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA
- TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256
- TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA
- TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256
- SSL_DH_anon_WITH_DES_CBC_SHA
- SSL_DH_anon_WITH_RC4_128_MD5
- TLS_DH_anon_WITH_SEED_CBC_SHA
- SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA
- SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA
- TLS_DH_DSS_WITH_AES_128_CBC_SHA
- TLS_DH_DSS_WITH_AES_128_CBC_SHA256
- TLS_DH_DSS_WITH_AES_128_GCM_SHA256
- TLS_DH_DSS_WITH_AES_256_CBC_SHA
- TLS_DH_DSS_WITH_AES_256_CBC_SHA256
- TLS_DH_DSS_WITH_AES_256_GCM_SHA384
- TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA
- TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256
- TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA
- TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256
- SSL_DH_DSS_WITH_DES_CBC_SHA
- TLS_DH_DSS_WITH_SEED_CBC_SHA
- SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA
- SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA
- TLS_DH_RSA_WITH_AES_128_CBC_SHA
- TLS_DH_RSA_WITH_AES_128_CBC_SHA256
- TLS_DH_RSA_WITH_AES_128_GCM_SHA256
- TLS_DH_RSA_WITH_AES_256_CBC_SHA
- TLS_DH_RSA_WITH_AES_256_CBC_SHA256
- TLS_DH_RSA_WITH_AES_256_GCM_SHA384
- TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA
- TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256
- TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA
- TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256
- SSL_DH_RSA_WITH_DES_CBC_SHA
- TLS_DH_RSA_WITH_SEED_CBC_SHA
- SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
- SSL_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA
- SSL_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA
- SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA
- TLS_DHE_DSS_WITH_AES_128_CBC_SHA
- TLS_DHE_DSS_WITH_AES_128_CBC_SHA256
- TLS_DHE_DSS_WITH_AES_128_GCM_SHA256
- TLS_DHE_DSS_WITH_AES_256_CBC_SHA
- TLS_DHE_DSS_WITH_AES_256_CBC_SHA256
- TLS_DHE_DSS_WITH_AES_256_GCM_SHA384
- TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA
- TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256
- TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA
- TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256
- SSL_DHE_DSS_WITH_DES_CBC_SHA
- SSL_DHE_DSS_WITH_RC4_128_SHA
- TLS_DHE_DSS_WITH_SEED_CBC_SHA
- TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA
- TLS_DHE_PSK_WITH_AES_128_CBC_SHA
- TLS_DHE_PSK_WITH_AES_128_CBC_SHA256
- TLS_DHE_PSK_WITH_AES_128_GCM_SHA256
- TLS_DHE_PSK_WITH_AES_256_CBC_SHA
- TLS_DHE_PSK_WITH_AES_256_CBC_SHA384
- TLS_DHE_PSK_WITH_AES_256_GCM_SHA384
- TLS_DHE_PSK_WITH_NULL_SHA
- TLS_DHE_PSK_WITH_NULL_SHA256
- TLS_DHE_PSK_WITH_NULL_SHA384
- TLS_DHE_PSK_WITH_RC4_128_SHA
- SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
- SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA
- TLS_DHE_RSA_WITH_AES_128_CBC_SHA
- TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
- TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
- TLS_DHE_RSA_WITH_AES_256_CBC_SHA
- TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
- TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
- TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
- TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
- TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
- TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256
- SSL_DHE_RSA_WITH_DES_CBC_SHA
- TLS_DHE_RSA_WITH_SEED_CBC_SHA
- TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA
- TLS_ECDH_anon_WITH_AES_128_CBC_SHA
- TLS_ECDH_anon_WITH_AES_256_CBC_SHA
- TLS_ECDH_anon_WITH_NULL_SHA
- TLS_ECDH_anon_WITH_RC4_128_SHA
- TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
- TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
- TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
- TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
- TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
- TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
- TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
- TLS_ECDH_ECDSA_WITH_NULL_SHA
- TLS_ECDH_ECDSA_WITH_RC4_128_SHA
- TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
- TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
- TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
- TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
- TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
- TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
- TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
- TLS_ECDH_RSA_WITH_NULL_SHA
- TLS_ECDH_RSA_WITH_RC4_128_SHA
- TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
- TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
- TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
- TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
- TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
- TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_ECDSA_WITH_NULL_SHA
- TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
- TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA
- TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA
- TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256
- TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA
- TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384
- TLS_ECDHE_PSK_WITH_NULL_SHA
- TLS_ECDHE_PSK_WITH_NULL_SHA256
- TLS_ECDHE_PSK_WITH_NULL_SHA384
- TLS_ECDHE_PSK_WITH_RC4_128_SHA
- TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
- TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
- TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
- TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
- TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
- TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_RSA_WITH_NULL_SHA
- TLS_ECDHE_RSA_WITH_RC4_128_SHA
- TLS_EMPTY_RENEGOTIATION_INFO_SCSV **[\*](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#footnote)**
- SSL_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA
- SSL_FORTEZZA_DMS_WITH_NULL_SHA
- TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5
- TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA
- TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5
- TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA
- TLS_KRB5_EXPORT_WITH_RC4_40_MD5
- TLS_KRB5_EXPORT_WITH_RC4_40_SHA
- TLS_KRB5_WITH_3DES_EDE_CBC_MD5
- TLS_KRB5_WITH_3DES_EDE_CBC_SHA
- TLS_KRB5_WITH_DES_CBC_MD5
- TLS_KRB5_WITH_DES_CBC_SHA
- TLS_KRB5_WITH_IDEA_CBC_MD5
- TLS_KRB5_WITH_IDEA_CBC_SHA
- TLS_KRB5_WITH_RC4_128_MD5
- TLS_KRB5_WITH_RC4_128_SHA
- TLS_PSK_WITH_3DES_EDE_CBC_SHA
- TLS_PSK_WITH_AES_128_CBC_SHA
- TLS_PSK_WITH_AES_128_CBC_SHA256
- TLS_PSK_WITH_AES_128_GCM_SHA256
- TLS_PSK_WITH_AES_256_CBC_SHA
- TLS_PSK_WITH_AES_256_CBC_SHA384
- TLS_PSK_WITH_AES_256_GCM_SHA384
- TLS_PSK_WITH_NULL_SHA
- TLS_PSK_WITH_NULL_SHA256
- TLS_PSK_WITH_NULL_SHA384
- TLS_PSK_WITH_RC4_128_SHA
- SSL_RSA_EXPORT_WITH_DES40_CBC_SHA
- SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5
- SSL_RSA_EXPORT_WITH_RC4_40_MD5
- SSL_RSA_EXPORT1024_WITH_DES_CBC_SHA
- SSL_RSA_EXPORT1024_WITH_RC4_56_SHA
- SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA
- SSL_RSA_FIPS_WITH_DES_CBC_SHA
- TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA
- TLS_RSA_PSK_WITH_AES_128_CBC_SHA
- TLS_RSA_PSK_WITH_AES_128_CBC_SHA256
- TLS_RSA_PSK_WITH_AES_128_GCM_SHA256
- TLS_RSA_PSK_WITH_AES_256_CBC_SHA
- TLS_RSA_PSK_WITH_AES_256_CBC_SHA384
- TLS_RSA_PSK_WITH_AES_256_GCM_SHA384
- TLS_RSA_PSK_WITH_NULL_SHA
- TLS_RSA_PSK_WITH_NULL_SHA256
- TLS_RSA_PSK_WITH_NULL_SHA384
- TLS_RSA_PSK_WITH_RC4_128_SHA
- SSL_RSA_WITH_3DES_EDE_CBC_SHA
- TLS_RSA_WITH_AES_128_CBC_SHA
- TLS_RSA_WITH_AES_128_CBC_SHA256
- TLS_RSA_WITH_AES_128_GCM_SHA256
- TLS_RSA_WITH_AES_256_CBC_SHA
- TLS_RSA_WITH_AES_256_CBC_SHA256
- TLS_RSA_WITH_AES_256_GCM_SHA384
- TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
- TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256
- TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
- TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256
- SSL_RSA_WITH_DES_CBC_SHA
- SSL_RSA_WITH_IDEA_CBC_SHA
- SSL_RSA_WITH_NULL_MD5
- SSL_RSA_WITH_NULL_SHA
- TLS_RSA_WITH_NULL_SHA256
- SSL_RSA_WITH_RC4_128_MD5
- SSL_RSA_WITH_RC4_128_SHA
- TLS_RSA_WITH_SEED_CBC_SHA
- TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA
- TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA
- TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA
- TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA
- TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA
- TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA
- TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA
- TLS_SRP_SHA_WITH_AES_128_CBC_SHA
- TLS_SRP_SHA_WITH_AES_256_CBC_SHA

\* `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` is a new pseudo-cipher suite to support RFC 5746. Read the [Transport Layer Security (TLS) Renegotiation Issue](https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html#tlsRenegotiation) section of the JSEE Reference Guide for more information.

## Additional JSSE Standard Names

The `keyType` parameter passed to the `chooseClientAlias`, `chooseServerAlias`, `getClientAliases`, and `getServerAliases` methods of `X509KeyManager` specifies the public key types. Each row of the table that follows lists the standard name that should be used for `keyType`, given the specified certificate type.

| Name       | Certificate Type                    |
| ---------- | ----------------------------------- |
| RSA        | RSA                                 |
| DSA        | DSA                                 |
| DH_RSA     | Diffie-Hellman with RSA signature   |
| DH_DSA     | Diffie-Hellman with DSA signature   |
| EC         | Elliptic Curve                      |
| EC_EC      | Elliptic Curve with ECDSA signature |
| EC_RSA     | Elliptic Curve with RSA signature   |
| RSASSA-PSS | RSASSA-PSS                          |

The `protocols` parameter passed to the `setEnabledProtocols` method of `SSLSocket` specifies the protocol versions to be enabled for use on the connection. The table that follows lists the standard names that can be passed to `setEnabledProtocols` or that may be returned by the `SSLSocket getSupportedProtocols` and `getEnabledProtocols` methods.

| Name       | Protocol                                                     |
| ---------- | ------------------------------------------------------------ |
| SSLv2      | SSL version 2 protocol                                       |
| SSLv3      | SSL version 3 protocol                                       |
| TLSv1      | TLS version 1.0 protocol (defined in [RFC 2246](https://tools.ietf.org/html/rfc2246)) |
| TLSv1.1    | TLS version 1.1 protocol (defined in [RFC 4346](https://tools.ietf.org/html/rfc4346)) |
| TLSv1.2    | TLS version 1.2 protocol (defined in [RFC 5246](https://tools.ietf.org/html/rfc5246)) |
| SSLv2Hello | Currently, the SSLv3, TLSv1, and TLSv1.1 protocols allow you to send SSLv3, TLSv1, and TLSv1.1 hellos encapsulated in an SSLv2 format hello. For more details on the reasons for allowing this compatibility in these protocols, see Appendix E in the appropriate RFCs (previously listed).  Note that some SSL/TLS servers do not support the v2 hello format and require that client hellos conform to the SSLv3 or TLSv1 client hello formats.  The SSLv2Hello option controls the SSLv2 encapsulation. If SSLv2Hello is disabled on the client, then all outgoing messages will conform to the SSLv3/TLSv1 client hello format. If SSLv2Hello is disabled on the server, then all incoming messages must conform to the SSLv3/TLSv1 client hello format. |

The `authType` parameter passed to the `checkClientTrusted` and `checkServerTrusted` methods of `X509TrustManager` indicates the authentication type. The table that follows specifies what standard names should be used for the client or server certificate chains.

| Client or Server Certificate Chain | Authentication Type Standard Name                            |
| ---------------------------------- | ------------------------------------------------------------ |
| Client                             | Determined by the actual certificate used. For instance, if RSAPublicKey is used, the `authType` should be "RSA". |
| Server                             | The key exchange algorithm portion of the cipher suites represented as a String, such as "RSA" or "DHE_DSS". Note: For some exportable cipher suites, the key exchange algorithm is determined at runtime during the handshake. For instance, for TLS_RSA_EXPORT_WITH_RC4_40_MD5, the `authType` should be "RSA_EXPORT" when an ephemeral RSA key is used for the key exchange, and "RSA" when the key from the server certificate is used. Or it can take the value "UNKNOWN". |

The JDK 8 release supports endpoint identification algorithms. The algorithm name can be passed to the `setEndpointIdentificationAlgorithm()` method of `javax.net.ssl.SSLParameters`. The following table shows the currently recognized names.

| Endpoint Identification Algorithm Name | Specification                                   |
| -------------------------------------- | ----------------------------------------------- |
| HTTPS                                  | [RFC 2818](https://tools.ietf.org/html/rfc2818) |
| LDAPS                                  | [RFC 2830](https://tools.ietf.org/html/rfc2830) |

------

## Algorithms

This section specifies details concerning some of the algorithms defined in this document. Any provider supplying an implementation of the listed algorithms must comply with the specifications in this section.

To add a new algorithm not specified here, you should first survey other people or companies supplying provider packages to see if they have already added that algorithm, and, if so, use the definitions they published, if available. Otherwise, you should create and make available a template, similar to those found in this section, with the specifications for the algorithm you provide.

## Specification Template

The following table shows the fields of the algorithm specifications.

| **Field**                        | **Description**                                              |
| -------------------------------- | ------------------------------------------------------------ |
| Name                             | The name by which the algorithm is known. This is the name passed to the `getInstance` method (when requesting the algorithm), and returned by the `getAlgorithm` method to determine the name of an existing algorithm object. These methods are in the relevant engine classes: `Signature`, `MessageDigest`, `KeyPairGenerator`, and `AlgorithmParameterGenerator` . |
| Type                             | The type of algorithm: `Signature`, `MessageDigest`, `KeyPairGenerator`, or `AlgorithmParameterGenerator`. |
| Description                      | General notes about the algorithm, including any standards implemented by the algorithm, applicable patents, and so on. |
| `KeyPair` Algorithm (*optional*) | The keypair algorithm for this algorithm.                    |
| Keysize (*optional*)             | For a keyed algorithm or key generation algorithm: the valid keysizes. |
| Size (*optional*)                | For an algorithm parameter generation algorithm: the valid "sizes" for algorithm parameter generation. |
| Parameter Defaults (*optional*)  | For a key generation algorithm: the default parameter values. |
| `Signature` Format (*optional*)  | For a `Signature` algorithm, the format of the signature, that is, the input and output of the verify and sign methods, respectively. |

## Algorithm Specifications

### SHA-1 Message Digest Algorithm

| Field           | Description                                                  |
| --------------- | ------------------------------------------------------------ |
| **Name**        | SHA-1                                                        |
| **Type**        | `MessageDigest`                                              |
| **Description** | The message digest algorithm as defined in [NIST's FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final). The output of this algorithm is a 160-bit digest. |

### SHA-224 Message Digest Algorithm

| Field           | Description                                                  |
| --------------- | ------------------------------------------------------------ |
| **Name**        | SHA-224                                                      |
| **Type**        | `MessageDigest`                                              |
| **Description** | The message digest algorithm as defined in [NIST's FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final). The output of this algorithm is a 224-bit digest. |

### SHA-256 Message Digest Algorithm

| Field           | Description                                                  |
| --------------- | ------------------------------------------------------------ |
| **Name**        | SHA-256                                                      |
| **Type**        | `MessageDigest`                                              |
| **Description** | The message digest algorithm as defined in [NIST's FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final). The output of this algorithm is a 256-bit digest. |

### SHA-384 Message Digest Algorithm

| Field           | Description                                                  |
| --------------- | ------------------------------------------------------------ |
| **Name**        | SHA-384                                                      |
| **Type**        | `MessageDigest`                                              |
| **Description** | The message digest algorithm as defined in [NIST's FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final). The output of this algorithm is a 384-bit digest. |

### SHA-512 Message Digest Algorithm

| Field           | Description                                                  |
| --------------- | ------------------------------------------------------------ |
| **Name**        | SHA-512                                                      |
| **Type**        | `MessageDigest`                                              |
| **Description** | The message digest algorithm as defined in [NIST's FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final). The output of this algorithm is a 512-bit digest. |

### SHA-512/224 Message Digest Algorithm

| Field           | Description                                                  |
| --------------- | ------------------------------------------------------------ |
| **Name**        | SHA-512/224                                                  |
| **Type**        | `MessageDigest`                                              |
| **Description** | The message digest algorithm as defined in [NIST's FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final). The output of this algorithm is a 224-bit digest. |

### SHA-512/256 Message Digest Algorithm

| Field           | Description                                                  |
| --------------- | ------------------------------------------------------------ |
| **Name**        | SHA-512/256                                                  |
| **Type**        | `MessageDigest`                                              |
| **Description** | The message digest algorithm as defined in [NIST's FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final). The output of this algorithm is a 256-bit digest. |

### MD2 Message Digest Algorithm

| Field           | Description                                                  |
| --------------- | ------------------------------------------------------------ |
| **Name**        | MD2                                                          |
| **Type**        | `MessageDigest`                                              |
| **Description** | The message digest algorithm as defined in [RFC 1319](https://tools.ietf.org/html/rfc1319). The output of this algorithm is a 128-bit (16 byte) digest. |

### MD5 Message Digest Algorithm

| Field           | Description                                                  |
| --------------- | ------------------------------------------------------------ |
| **Name**        | MD5                                                          |
| **Type**        | `MessageDigest`                                              |
| **Description** | The message digest algorithm as defined in [RFC 1321](https://tools.ietf.org/html/rfc1321). The output of this algorithm is a 128-bit (16 byte) digest. |

### The Digital Signature Algorithm, with SHA-1 or SHA-2

| Field                   | Description                                                  |
| ----------------------- | ------------------------------------------------------------ |
| **Name**                | SHA1withDSA, SHA224withDSA, SHA256withDSA, SHA384withDSA, and SHA512withDSA |
| **Type**                | `Signature`                                                  |
| **Description**         | This algorithm is the signature algorithm described in [NIST FIPS 186-4](https://csrc.nist.gov/publications/detail/fips/186/4/final), using DSA with the SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512 message digest algorithms. |
| **`KeyPair` Algorithm** | DSA                                                          |
| **Signature Format**    | ASN.1 sequence of two INTEGER values: `r` and `s`, in that order: `SEQUENCE ::= { r INTEGER, s INTEGER }` |

### RSA-based Signature Algorithms, with MD2, MD5, SHA-1, or SHA-2

| Field                   | Description                                                  |
| ----------------------- | ------------------------------------------------------------ |
| **Names**               | MD2withRSA, MD5withRSA, SHA1withRSA, SHA224withRSA, SHA256withRSA, SHA384withRSA, SHA512withRSA, SHA512/224withRSA, SHA512/256withRSA |
| **Type**                | `Signature`                                                  |
| **Description**         | These are the signature algorithms that use the MD2, MD5, SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512 message digest algorithms (respectively) with RSA encryption. |
| **`KeyPair` Algorithm** | RSA                                                          |
| **Signature Format**    | DER-encoded PKCS1 block as defined in [RSA Laboratories, PKCS #1 v2.2](https://tools.ietf.org/html/rfc8017). The data encrypted is the digest of the data signed. |

### RSASSA-PSS-based Signature Algorithms

| Field                   | Description                                                  |
| ----------------------- | ------------------------------------------------------------ |
| **Names**               | RSASSA-PSS                                                   |
| **Type**                | `Signature`                                                  |
| **Description**         | This signature algorithm requires PSS parameters to be explicitly supplied before data can be processed. |
| **`KeyPair` Algorithm** | RSA or RSASSA-PSS                                            |
| **Signature Format**    | DER-encoded PKCS1 block as defined in [RSA Laboratories, PKCS #1 v2.2](https://tools.ietf.org/html/rfc8017). The data encrypted is the digest of the data signed. |

### DSA KeyPair Generation Algorithm

| Field                  | Description                                                  |
| ---------------------- | ------------------------------------------------------------ |
| **Name**               | DSA                                                          |
| **Type**               | `KeyPairGenerator`                                           |
| **Description**        | This algorithm is the key pair generation algorithm described [NIST FIPS 186](https://csrc.nist.gov/publications/detail/fips/186/4/final) for DSA. |
| **Keysize**            | The length, in bits, of the modulus *p*. This must be a multiple of 64, ranging from 512 to 1024 (inclusive), or 2048. The default keysize is 1024. |
| **Parameter Defaults** |                                                              |

### RSA KeyPair Generation Algorithm

| Field           | Description                                                  |
| --------------- | ------------------------------------------------------------ |
| **Names**       | RSA                                                          |
| **Type**        | `KeyPairGenerator`                                           |
| **Description** | This algorithm is the key pair generation algorithm described in [PKCS #1 v2.2](https://tools.ietf.org/html/rfc8017). |
| **Strength**    | The length, in bits, of the modulus *n*. This must be a multiple of 8 that is greater than or equal to 512 |

### RSASSA-PSS KeyPair Generation Algorithm

| Field           | Description                                                  |
| --------------- | ------------------------------------------------------------ |
| **Names**       | RSASSA-PSS                                                   |
| **Type**        | `KeyPairGenerator`                                           |
| **Description** | This algorithm is the key pair generation algorithm described in [PKCS #1 v2.2](https://tools.ietf.org/html/rfc8017). |
| **Strength**    | The length, in bits, of the modulus *n*. This must be a multiple of 8 that is greater than or equal to 512. |

### DSA Parameter Generation Algorithm

| Field           | Description                                                  |
| --------------- | ------------------------------------------------------------ |
| **Names**       | DSA                                                          |
| **Type**        | `AlgorithmParameterGenerator`                                |
| **Description** | This algorithm is the parameter generation algorithm described in [NIST FIPS 186](https://csrc.nist.gov/publications/detail/fips/186/4/final) for DSA. |
| **Strength**    | The length, in bits, of the modulus *p*. This must be a multiple of 64, ranging from from 512 to 1024 (inclusive), or 2048. The default keysize is 1024.Alternatively, generate DSA parameters with the `DSAGenParameterSpec `class. Note that this class supports the latest version of DSA standard, [FIPS PUB 186-4](https://csrc.nist.gov/publications/detail/fips/186/4/final), and only allows certain length of prime P and Q to be used. Valid sizes for length of prime P and sub-prime Q in bits are as follows:(1024, 160)(2048, 224)(2048, 256) |



------

## Implementation Requirements

This section defines the security algorithm requirements for JDK 8 implementations. These requirements are intended to improve the interoperability of JDK 8 implementations and applications that use these algorithms.

Note that the requirements in this section are **not** a measure of the strength or security of the algorithm. For example, recent advances in cryptanalysis have found weaknesses in the strength of the MD5 MessageDigest algorithm. It is your responsibility to determine whether the algorithm meets the security requirements of your application.

Every implementation of the JDK 8 platform must support the specified algorithms in the table that follows. These requirements do not apply to third party providers. Consult the release documentation for your implementation to see if any other algorithms are supported.

| Class                                                        | Algorithm Name(s)                                            |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `AlgorithmParameterGenerator` Implementations must support the key sizes in parentheses. | DiffieHellman (1024) DSA (1024)                              |
| `AlgorithmParameters`                                        | AES DES DESede DiffieHellman DSA                             |
| `CertificateFactory`                                         | X.509                                                        |
| `CertPath` Encodings                                         | PKCS7 PkiPath                                                |
| `CertPathBuilder`                                            | PKIX                                                         |
| `CertPathValidator`                                          | PKIX                                                         |
| `CertStore`                                                  | Collection                                                   |
| `Cipher` The algorithms are specified as [transformations](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#trans). Implementations must support the key sizes in parentheses. | AES/CBC/NoPadding (128) AES/CBC/PKCS5Padding (128) AES/ECB/NoPadding (128) AES/ECB/PKCS5Padding (128) DES/CBC/NoPadding (56) DES/CBC/PKCS5Padding (56) DES/ECB/NoPadding (56) DES/ECB/PKCS5Padding (56) DESede/CBC/NoPadding (168) DESede/CBC/PKCS5Padding (168) DESede/ECB/NoPadding (168) DESede/ECB/PKCS5Padding (168) RSA/ECB/PKCS1Padding (1024, 2048) RSA/ECB/OAEPWithSHA-1AndMGF1Padding (1024, 2048) RSA/ECB/OAEPWithSHA-256AndMGF1Padding (1024, 2048) |
| `Configuration` [[1\]](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#impl) |                                                              |
| `KeyAgreement`                                               | DiffieHellman                                                |
| `KeyFactory`                                                 | DiffieHellman DSA RSA                                        |
| `KeyGenerator` Implementations must support the key sizes in parentheses. | AES (128) DES (56) DESede (168) HmacSHA1 HmacSHA256          |
| `KeyPairGenerator` Implementations must support the key sizes in parentheses. | DiffieHellman (1024) DSA (1024) RSA (1024, 2048)             |
| `KeyStore`                                                   | PKCS12                                                       |
| `Mac`                                                        | HmacMD5 HmacSHA1 HmacSHA256                                  |
| `MessageDigest`                                              | MD5 SHA-1 SHA-256                                            |
| `Policy` [[1\]](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#impl) |                                                              |
| `SecretKeyFactory`                                           | DES DESede                                                   |
| `SecureRandom` [[1\]](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#impl) |                                                              |
| `Signature`                                                  | SHA1withDSA SHA1withRSA SHA256withRSA                        |
| `SSLContext`                                                 | TLSv1 [[2\]](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#footnote) |

[1] No specific `Configuration` type, `Policy` type or `SecureRandom` algorithm is required; however, an implementation-specific default must be provided.

[2] A TLSv1 implementation must support the cipher suite SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA as defined in [RFC 2246](https://tools.ietf.org/html/rfc2246) and the special signaling cipher suite TLS_EMPTY_RENEGOTIATION_INFO_SCSV for safe renegotiation as defined in [RFC 5746](https://tools.ietf.org/html/rfc5746).

## XML Signature Algorithms

Every implementation of the JDK 8 platform must support the specified XML Signature algorithms in the table that follows. These requirements do not apply to 3rd party providers. Consult the release documentation for your implementation to see if any other algorithms are supported.

| Class                 | Algorithm Name(s)                                            |
| --------------------- | ------------------------------------------------------------ |
| `TransformService`    | http://www.w3.org/2001/10/xml-exc-c14n# (`CanonicalizationMethod.EXCLUSIVE`) http://www.w3.org/TR/2001/REC-xml-c14n-20010315 (`CanonicalizationMethod.INCLUSIVE`) http://www.w3.org/2000/09/xmldsig#base64 (`Transform.BASE64`) http://www.w3.org/2000/09/xmldsig#enveloped-signature (`Transform.ENVELOPED`) |
| `XMLSignatureFactory` | DOM                                                          |

