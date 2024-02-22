# Verifying

## Overview

Steps required to verify using high assurance

TODO

## Demo Verification Script

A Python demo script is available: [Demo.py](./scripts/Demo.py). Before you run the script be sure you have created your virtual environment and installed the dependencies outlined in [README](./README.md)

## Verify DID DOC

This script does verify a did doc [verify_did_doc.py](./scripts/verify_did_doc.py) on a test site [lncreds.ca](https://lncreds.ca).

This example uses the secp256k1 library and ecdsa signature which is popular in the Bitcoin and decentralized ecosystems. It is not the only option.

Note: This example follows JWT conventions in the context of a DID doc. This is not currently part of the W3C DID standard but may be incorporated in later revisions

The verification logic is as follows:

- Given the following:
  - domain name is: ```lncreds.ca```
  - the corresponding did:web is ```did:web:lncreds.ca```
- Look up pubkey record in DNS/DNSSEC
  - the corresponding pubkey record is a TXT record at _pubkey. This pubkey is set by the domain owner and can be independently set from the website operator serving the did:web identifier.
- Download the did doc
  - download the did doc from the REST endpoin derived from the did:web identitier
  - if DNSSEC check against corresponding RRSIG record (not implemented yet)
- Verify the did doc   
  - extract elements required for verification
    - iss: the pubkey of the issuer
    - exp: the expiry datetime (or TTL)
    - signature: the signature required to verify the did doc
  - remove sections from did_doc that are not signed
    - these sections can be treated as metadata, and removed before signature verification.
    - ```"@context", "header", and "signature"```
  - Checke to see if iss == pubkey record looked up in DNS/DNSSEC
  - Check to see if did doc is not expired
  - Check remaining payload if propertly signed with signature
  - If all checks pass, return TRUE, else return FALSE

## Verifying with dig

this shows the TLSA record and the corresponding RRSIG record

```bash
dig +dnssec @ns1.desec.io _443._tcp.trustroot.ca
```
