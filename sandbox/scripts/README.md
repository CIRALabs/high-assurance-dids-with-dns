# Scripts README for High Assurance DID WEB

## Introduction

This directory contains instructions and practical examples on how to leverage the scripts here in to create and interact with the technology and infrastructure necessary for a high assurance ```did:web```.

## Notes on Setting Up a Sandbox Environment

This repository includes hands-on examples to gain practical experience for implementation. A few experimental Python scripts are provided in the scripts directory. To prepare, clone this repo into a working directory.

If you wish to run these scripts it is advisable that you set up a 'sandbox' or a virtual environment. You then need to activate this environment and install the dependencies.

To set up your virtual environment and run the scripts run the following in your working directory.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cd scripts
```

## The Scripts

### 1. generate_verification_method.py

usage: `generate_verification_method.py [-h] {ed25519,ecdsasecp256k1} {jwk,multibase} did verification_method_id`

Generates a private/public key pair and verification method corresponding to the key type and representation selected.

Args:
**Key Types**:
[ed25519](https://ed25519.cr.yp.to/#:~:text=Ed25519%20is%20a%20public%2Dkey,Nehalem%2FWestmere%20lines%20of%20CPUs)
[ecdsasecp256k1](https://2finance.medium.com/understanding-elliptic-curve-digital-signature-algorithm-ecdsa-secp256k1-and-eddsa-curve25519-56ff82fc4f74)
**VerificationMethod Type**:
[jwk](https://www.w3.org/TR/did-core/#verification-material)
[multibase](https://www.w3.org/TR/did-core/#verification-material)
**did**: Specifies the controller of the verificationMethod being generated and root of the id for the verificationMethod.
**verification_method_id**: Specifies the id of the verificationMethod being generated.

Note: This script could easily be extended to support more key types. Note that the `multibase` option will output they keys in PEM format for user convenience.

Ex: `python3 generate_verification_method.py ed25519 j
wk did:example.ca key-1`
```json
Private key:
{
    "crv": "Ed25519",
    "x": "fDGT6iwtLl6oXCI6dVxeyMw8I-ZwwpjMqJMUm8zWKFs",
    "d": "2DlDDC-W51Z52_VR9YGFkcn043ZS9vpmUf3TcjACG_4",
    "kty": "OKP"
}

Public key:
{
    "crv": "Ed25519",
    "x": "fDGT6iwtLl6oXCI6dVxeyMw8I-ZwwpjMqJMUm8zWKFs",
    "kty": "OKP"
}

VerificationMethod:
{
    "id": "did:example.ca#did:example.ca#key-1",
    "type": "Ed25519VerificationKey2018",
    "controller": "did:example.ca",
    "publicKeyJwk": {
        "crv": "Ed25519",
        "x": "fDGT6iwtLl6oXCI6dVxeyMw8I-ZwwpjMqJMUm8zWKFs",
        "kty": "OKP"
    }
}
```

### 2. generate_tlsa_record_from_verification_method.py

usage: `generate_tlsa_record_from_verification_method.py [-h] [-hash] did`

Generates a [TLSA record](https://www.dynu.com/Resources/DNS-Records/TLSA-Record) from a verificationMethod. Supports publicKeyJwk and Multibase format verificationMethods. The script will resolve a did either directly from the url if did:web, or via the [Universal Resolver](https://dev.uniresolver.io/) if another did:method. Will prompt the user to select which verificationMethod in the did document they wish to generate the TLSA record for.

If the user wishes to use a hash of the verificationMethod instead of it unhashed they can supply the `-hash` option.

Ex: `python3 generate_tlsa_record_from_verification_method.py did:web:trustregistry.ca`
```json
Select a verification method:
1. did:web:trustregistry.ca#key-1
Enter the number of the verification method: 1
3 1 0 302a300506032b657003210090194851cc686b2628562246a98f190e486023d8bcef124fa7ea08284cc7bf67
```

The record content can then be used to create a corresponding _did TLSA record on your DNS infrastructure or via your DNS provider.

### 3. generate_did_doc_proof.py

usage: `generate_did_doc_proof.py [-h] [-v] {ecdsa-jcs-2019,eddsa-jcs-2022} did verification_method expiry path`

Generates a DID doc proof using either the [ecdsa-jcs-2019](https://www.w3.org/TR/vc-di-ecdsa/#ecdsa-jcs-2019) or [eddsa-jcs-2022](https://www.w3.org/TR/vc-di-eddsa/#eddsa-jcs-2022) formats. If the did is a did:web it will download the did document directly from the url, if it is another did method it will download it using the [Universal Resolver](https://dev.uniresolver.io/). The `-v` option if used will attempt to resolve the verificationMethod. It can be omitted to not perform this check. The did document is pruned of any existing proof object, is canonicalized, and then signed using the provided private key. The script supports and will automatically detect multibase, jwk, and PEM format keys. 

Note: Key types should correspond to the proof type being generated, i.e an ecdsa key should be used to create an ecdsa-jcs-2019 proof.

**Proof Types**:
[ecdsa-jcs-2019](https://www.w3.org/TR/vc-di-ecdsa/#ecdsa-jcs-2019)
[eddsa-jcs-2022](https://www.w3.org/TR/vc-di-eddsa/#eddsa-jcs-2022)
**did**: Specifies the did to generate the proof for
verification_method: Specifies the verificationMethod corresponding to the private key used to generate the proof.
**expiry**: ISO Date format specifying the expiry for the proof.
**path**: Path to the private key used to sign the proof.
**-v**: Attempts to resolve the specified verificationMethod.

Ex: `python3 generate_did_doc_proof.py eddsa-jcs-2022 did:web:trustregistry.ca did:web:example.ca#key-1 2024-03-21T01:48:19 ./keys/ed25519-2-priv.pem`
```json
{
    "proof": {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "verificationMethod": "did:web:example.ca#key-1",
        "created": "2024-03-20T21:55:31",
        "expires": "2024-03-21T01:48:19",
        "proofValue": "z4rvUt3Pwm26PyidmSSVHjV1bK7CLhqanjf4R8wFAWnjmQY2qP8HNhQdJ441WXqeh2BLtsmhAn55zHDcALo1Gpkjq"
    }
}
```

### 4. dns_lookup.py
usage: `dns_lookup.py [-h] [--dnssec] [--verbose] record_name {uri,tlsa,ds,dnskey,a,aaaa,cname,mx,ns}`

Attemps to resolve the specified DNS record with optional DNSSEC validation of the existing and first parent of the domain (i.e If querying trustregistry.ca, the script will validate the RRSIGS for the resolved record match the DNSKEY in the trustregistry.ca zone, and then verifies the corresponding DS records are in the .ca zone). The `--verbose` option will provide additional logging for DNS and DNSSEC validation.

Ex: `python3 dns_lookup.py --dnssec --verbose _did.trustregistry.ca tlsa`
```json
INFO:root:DNSKEY records: trustregistry.ca. 21600 IN DNSKEY 257 3 13 F6eUlQzojRNGXZYBUfWN53Uix8Hkhl/B e8aMpw25m/E+ZbB6kwW6KNHtBQEXtB4P RUd7GctK4AjUGwjWDqpk2g==
INFO:root:DS records: trustregistry.ca. 21600 IN DS 16050 13 2 bed475b1dc7a18c0a6402e68c42425cdcae241a2b8b417607499b8bca751e763
trustregistry.ca. 21600 IN DS 16050 13 4 981ede0ccb5d8414d434f4aaf907324ba155b14015b1e9cb4cba1aa48d0a4ac591a2ddaaba6ff6b353761e3b4d058ae7
INFO:root:DNSKEY validation passed for 257 3 13 F6eUlQzojRNGXZYBUfWN53Uix8Hkhl/B e8aMpw25m/E+ZbB6kwW6KNHtBQEXtB4P RUd7GctK4AjUGwjWDqpk2g==
INFO:root:RRSET: _did.trustregistry.ca. 3600 IN TLSA 3 1 0 302a300506032b657003210090194851cc686b2628562246a98f190e486023d8bcef124fa7ea08284cc7bf67
_did.trustregistry.ca. 3600 IN TLSA 3 1 1 218e4259e6bb4a4ec56e7ed3a4ce9a6ae399cfef2655fb9a7f51161c1bce157a
INFO:root:RRSIG: _did.trustregistry.ca. 3600 IN RRSIG TLSA 13 3 3600 20240328000000 20240307000000 16050 trustregistry.ca. J7UH40R1aISrsm9Ukeuj/m4jtwx9RArg TgOZ+C6syy/9VbOu5msgHKqNaY2mj5uf s5lDNa8nUVoC0lJfURl/0Q==
INFO:root:
DNSSEC validation passed for _did.trustregistry.ca tlsa
_did.trustregistry.ca. 3600 IN TLSA 3 1 0 302a300506032b657003210090194851cc686b2628562246a98f190e486023d8bcef124fa7ea08284cc7bf67
_did.trustregistry.ca. 3600 IN TLSA 3 1 1 218e4259e6bb4a4ec56e7ed3a4ce9a6ae399cfef2655fb9a7f51161c1bce157a
```

### 5. verify_high_assurance_did_web.py
usage: `verify_high_assurance_did_web.py [-h] [--use-dns] [--use-dnssec] did`

Performs a validation of a high assurance did:web to various degress of assurance.

Without the `--use-dns` and `--use-dnssec` options, the script will simply resolve a did:web, verify the proof object is not expired, and verify the associated verificationMethod can validate the **proofValue** within.

To increase the level of assurance the `--use-dns` option may be supplied. This will query the domain pointed to the by the did:web (i.e did:web:example.ca will point to example.ca) for 2 _did prefixed DNS records. A TLSA record that matches the verificationMethod in the proof section, and a URI record which matches the did being verified.

TLSA Record: **_did.example.ca 3 1 0 SomeHexKey**
URI Record: **_did.example.ca 1 0 "did:web:example.ca"**

To further increase the level of assurance the `--use-dnssec` option may be included along with the `--use-dns` option to perform DNSSEC validation on the associated validation records up to the first parent of the domain (i.e In the case of did:web:example.ca, it will validate that the rrsigs for the _did URI and TLSA records match the DNSKEY for the example.ca zone, and then verify that the .ca zone has DS records corresponding to the DNSKEY).

Ex: `python3 verify_high_assurance_did_web.py --use-dns --use-dnssec did:web:trustregistry.ca`
```json
INFO:root:Resolved DID document for did:web:trustregistry.ca: {
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/jws-2020/v1",
    "https://github.com/trustoverip/tswg-trust-registry-service-profile/blob/main/spec.md"
  ],
  "id": "did:web:trustregistry.ca",
  "service": [
    {
      "id": "did:web:trustregistry.ca#linked-domain",
      "type": "LinkedDomains",
      "serviceEndpoint": "https://trustregistry.ca"
    },
    {
      "id": "did:web:trustregistry.ca#trust-registry",
      "type": "TrustRegistry",
      "serviceEndpoint": {
        "profile": "https://trustoverip.org/profiles/trp/v2",
        "uri": "https://trustregistry.ca/"
      }
    }
  ],
  "verificationMethod": [
    {
      "id": "did:web:trustregistry.ca#key-1",
      "type": "Ed25519VerificationKey2018",
      "controller": "did:web:trustregistry.ca",
      "publicKeyJwk": {
        "crv": "Ed25519",
        "x": "kBlIUcxoayYoViJGqY8ZDkhgI9i87xJPp-oIKEzHv2c",
        "kty": "OKP"
      }
    }
  ],
  "authentication": [
    "did:web:trustregistry.com#key-1"
  ],
  "assertionMethod": [
    "did:web:trustregistry.com#key-1"
  ],
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "verificationMethod": "did:web:trustregistry.ca#key-1",
    "created": "2024-03-11T16:34:29",
    "expires": "2025-03-11T20:23:04",
    "proofValue": "z39hGKXkkzGB5o2v3zkizb7ShXgpJAueZNRrNZ5VYZGBrxGXgead8VkEEb8DNwUyhu1U2rakDTjY88PA5WrYScT1r"
  }
}
INFO:root:Verifying DID document proof...
INFO:root:DID document proof: {
  "type": "DataIntegrityProof",
  "cryptosuite": "eddsa-jcs-2022",
  "verificationMethod": "did:web:trustregistry.ca#key-1",
  "created": "2024-03-11T16:34:29",
  "expires": "2025-03-11T20:23:04",
  "proofValue": "z39hGKXkkzGB5o2v3zkizb7ShXgpJAueZNRrNZ5VYZGBrxGXgead8VkEEb8DNwUyhu1U2rakDTjY88PA5WrYScT1r"
}
INFO:root:Signing verificationMethod: {
  "id": "did:web:trustregistry.ca#key-1",
  "type": "Ed25519VerificationKey2018",
  "controller": "did:web:trustregistry.ca",
  "publicKeyJwk": {
    "crv": "Ed25519",
    "x": "kBlIUcxoayYoViJGqY8ZDkhgI9i87xJPp-oIKEzHv2c",
    "kty": "OKP"
  }
}
INFO:root:Succesfully verified proof using: did:web:trustregistry.ca#key-1
INFO:root:Validating DID document using DNS records...
INFO:root:Validating URI record matches did:web:trustregistry.ca...
INFO:root:Performing DNSSEC validation for RdataType.URI record _did.trustregistry.ca...
INFO:root:DNSSEC validation succesfull for RdataType.URI record _did.trustregistry.ca.
INFO:root:Resolved URI records: _did.trustregistry.ca. 3600 IN URI 0 0 "did:web:trustregistry.ca"
INFO:root:URI record matches did:web:trustregistry.ca.
INFO:root:Validating TLSA record matches did:web:trustregistry.ca#key-1...
INFO:root:Performing DNSSEC validation for RdataType.TLSA record _did.trustregistry.ca...
INFO:root:DNSSEC validation succesfull for RdataType.TLSA record _did.trustregistry.ca.
INFO:root:Resolved TLSA records: _did.trustregistry.ca. 3600 IN TLSA 3 1 0 302a300506032b657003210090194851cc686b2628562246a98f190e486023d8bcef124fa7ea08284cc7bf67
_did.trustregistry.ca. 3600 IN TLSA 3 1 1 218e4259e6bb4a4ec56e7ed3a4ce9a6ae399cfef2655fb9a7f51161c1bce157a
INFO:root:TLSA record matches did:web:trustregistry.ca#key-1.
INFO:root:DNS validation successful.
```

## Key Resources and Prior Work

This project builds on and leverages prior work

* [IETF DRAFT Leveraging DNS in Digital Trust: Credential Exchanges and Trust Registries](https://www.ietf.org/id/draft-latour-dns-and-digital-trust-01.html)
* [CIRA A trust layer for the internet is emerging: a 2023 report](https://www.cira.ca/en/resources/documents/state-of-internet/a-trust-layer-for-the-internet-is-emerging-a-2023-report/)
* [CIRA A Trust Layer for the Internet is Emerging](https://www.cira.ca/uploads/2023/12/12222023_A-trust-layer-for-the-internet-is-emerging_-report-%E2%80%93-Continuum_CIRA.pdf)
* [TrustyDID](https://github.com/CIRALabs/TrustyDID)
* [W3C Data Integrity 1.0](https://www.w3.org/community/reports/credentials/CG-FINAL-data-integrity-20220722/)

