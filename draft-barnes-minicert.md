# Introduction

* X.509 is terrible
* Defining a new certificate format

# Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in RFC 2119 [RFC2119].

# Certificate Format

* Attribute certs vs. Authority certs
* TLS syntax below
* Note that the first 8 bytes determine the length of remainder
* This results in certificates of <300 bytes

~~~~~
struct {
  uint16 version;                         //     2 bytes
  uint16 keyAlgorithm;                    //     2
  uint16 sigAlgorithm;                    //     2
  Attribute attributes<0..2^16-1>;        //     2 + NN * (2 + 2 + N)
  uint64 notBefore;                       //     8
  uint64 notAfter;                        //     8
  opaque publicKey[keyAlgorithm.keySize]; //    32 .. 96
  opaque issuer[sigAlgorithm.issuerSize]; //    32 .. 48
  opaque signature[sigAlgorithm.sigSize]; //    64 .. 96
} AttributeCertificate                    // = 152+  264+

struct {
  uint16 version;                         //     2 bytes
  uint16 keyAlgorithm;                    //     2
  uint16 sigAlgorithm;                    //     2
  uint16 flags                            //     2
  uint64 notBefore;                       //     8
  uint64 notAfter;                        //     8
  opaque publicKey[keyAlgorithm.keySize]; //    32 .. 96
  opaque issuer[sigAlgorithm.issuerSize]; //    32 .. 48
  opaque signature[sigAlgorithm.sigSize]; //    64 .. 96
} AuthorityCertificate                    // = 152   264
~~~~~

## Parent / Child Relationships

* Two certificates form a parent/child pair iff the following are true:
  * parent.keyAlgorithm == child.sigAlgorithm
	* IssuerMatch(child.issuer, parent.key)
	* Verify(parent.key, child.TBS, child.sigAlgorithm)

## Cryptographic Algorithms

Algorithm MUST define the following:

* Fixed sizes for: (1) public keys, (2) issuer indicators, (3) signatures
* An algorithm for matching issuer indicators to public keys
* A signing algorithm
* A verification algorithm

### ECDSA with P-256 and SHA-256

* Key size: 64
* Issuer size: 32
* Signature size: 64
* Issuer match: SHA-256(key) == issuer
* Sign / Verify: ECDSA

### ECDSA with P-384 and SHA-384

* Key size: 96
* Issuer size: 48
* Signature size: 96
* Issuer match: SHA-384(key) == issuer
* Sign / Verify: ECDSA

### Ed25519

* Key size: 32
* Issuer size: 32
* Signature size: 64
* Issuer match: key == issuer
* Sign / Verify: Ed25519

### Ed448

* Key size: 57
* Issuer size: 57
* Signature size: 117
* Issuer match: key == issuer
* Sign / Verify: Ed448

# Certificate Verification

* A leaf certificate is a signed statement under a public key
* An authority certificate is a link from one key to another
* A certificate is valid iff it is connected 

## Parent / Child Relationship

* Certificates are connected to each other by signatures
* Algorithms are indicated with identifiers from a flat 16-bit space
* Algorithm MUST define:
	* Fixed sizes for: (1) public keys, (2) issuer indicators, (3) signatures
	* An algorithm for matching issuer indicators to public keys
	* A signing algorithm
	* A verification algorithm

## Path Building

* A sequence of CA certificates is "valid" for (leaf, trust anchor set):
  * The first certificate a parent of the leaf
  * The each subsequent certificate is a parent of the previous one
  * The last certificate is issued by a trust anchor
* All that matters is that you find a valid path
* You can use whatever graph-theoretic algorithms you want

# Revocation

* Certificates do not carry any information about revocation
* Applications MUST either:
  * Provide metadata about whether a certificate has been revoked
  * Limit the lifetime of certificates so that revocation is not needed

