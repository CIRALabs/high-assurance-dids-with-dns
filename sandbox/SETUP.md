# High Assurance DID Web Setup Instructions

## Background and Key Concepts

For true high assurance, everything must be cryptographically signed and the private keys of the owners and all delegates need to be under their control.

A high assurance did:web relies on two key signed documents - a signed DNS zone document and a signed decentralized identifier (DID) document (did doc, for short)

* A signed domain zone document, which is managed by a DNSSEC provider. Typically, this is presented a collection of signed DNS records, which can orignate from a signed zone document.
* A signed DID document, managed and created by the did:web:identifier operator which is usually the same entity as the domain owner (not in all cases, though).

Today, most implementations today do not sign their DNS records. They rely on sufficient administrator controls and  trusting the DNS provider to serve the right DNS records.

Similarly, for did:web identifiers, the website operator is trusted to serve the DID doc,and all information related to the did:web identitifier, including cryptographic keys used for signing and verification.

Unfortunately, this currrent approach requires significant trust of the DNS provider AND the website operator. There is no way to detect alterations. There is no cryptographic assurance, or high assurance.

This is the problem that high assurance did:web aims to solve: leveraging the existing infrastructure, DNS/DNSSEC and providing true cryptographic assurance of signed digital DNS records along with providing cryptographic keys that can sign did docs provided by did:web identifiers.

DNSSEC provides the assurance of the integrity of records by enabling digital signatures on the DNS records. With the addition of DNSSEC signed records that authoritatively bind a did:web to the domain and the addition of DNSSEC records (TLSA, CERT, TXT), it is also possible to bind website certificates, other certificates, and public keys to ensure the integrity of the DID doc provided by did:web.

The steps to create a high-assurance did:web are summarized below and detailed following in the document:

* Generate the necessary signing keys to sign DNSSEC records: These are the Key Signing Key (KSK) and the Zone Signing Key(ZSK).
* Retrieve the existing domain zone file.
* Retrieve or generate the necessary certificates or public keys that will be use to sign the DID doc. It can be the same website X.509 TLS certificate used for ```https```, it can be a new X.509 certificate generated for the purpose of signing, or it can be a public key, such as 32 byte hex string which is popular for other ecosystem.
* Add the necessary information to the existing domain zone file.
* Sign the domain zone file
* Deploy the signed domain file.

## Step 0: Prerequisites

The following software needs to be installed before you begin

* Install OPENSSL. You will need ```openssl```
* Install BIND Tools. You will need ```dnssec-keygen``` and ```dnssec-signzone```

## Step 1: Create Working Directory

* Create a working directory. If you have cloned this directory, open a terminal session and change to this directory
* Copy your zone file into the directory

## Step 2: Generate the Zone Signing Key (ZSK) and (KSK) for the zone

```bash
dnssec-keygen -a ECDSAP256SHA256 -n ZONE example.com
dnssec-keygen -f KSK -a ECDSAP256SHA256 -n ZONE example.com
```

you will see corresponding files for the keypairs

```bash
Kexample.com.+013+01920.key
Kexample.com.+013+01920.private
Kexample.com.+013+49732.key
Kexample.com.+013+49732.private

```

If you look at the ```.key``` files you will see the last line has records like this.

```base
example.com. IN DNSKEY 256 3 13 vTufUbS6qDQbte4pLIn/5PajjnzAPgWa3DS2z+gIBNiCh9BNnPwzZcsV qloYC/PFLAmqWaJhNfeJk6zXlMoqYA==
example.com. IN DNSKEY 257 3 13 F78A5WBwIskd8T/gjWcFVaBpZZ/8Zu6I6wqAzo4cmm/xZm/ZULpxJ/Gw l4bPkj9+ZnaT91yObjsziV0vnar9Zg==


```

```257``` means it's a Key Signing Key (KSK)
```256``` means its a Zone Signing Key (ZSK)

The KSK is used to sign the set of DNSKEY records in the zone, including other KSKs and any Zone Signing Keys (ZSKs).
The KSK is considered more critical for security than the ZSK. Because it signs the keys used to validate all the other records in the zone, its compromise can be more damaging. The KSK helps establish the chain of trust in DNSSEC.

The ZSK are used to sign other types of records in the zone, like A, AAAA, MX, etc.

You will need these record to modify the zone file to be signed.

## Step 3: Modify Zone File

Retrieve your zone file from your DNS provider. Your ```example.com.zone``` zone file should look something like below. Make sure you make a copy to work on, just in case you need to start over. The modified copy used in these instructions is ```example-mod.com.zone```

```bash
$TTL 3600      ; Default time-to-live value
@       IN      SOA     ns1.example.com. admin.example.com. (
                        2022010101      ; Serial
                        3600            ; Refresh
                        1800            ; Retry
                        604800          ; Expire
                        86400 )         ; Negative Cache TTL


; Name Server records
@       IN      NS      ns1.example.com.
@       IN      NS      ns2.example.com.

; A records for name servers
ns1     IN      A       192.0.2.1
ns2     IN      A       192.0.2.2

; A record for the domain
@       IN      A       192.0.2.100

; Additional records
www     IN      A       192.0.2.100
mail    IN      A       192.0.2.101
@       IN      MX 10   mail.example.com.

```

## Step 4: Add in the DID URI

```bash
_did.example.com. IN URI 10 1 "did:web:example.com"

```

## Step 5: Add in the TLS certificate and other certifictates

### Step 5a: Add in TLS certifications

You can add in your website certificate. Typically this the ```fullchain.pem``` that is created by the certificate authority.

If you don't have a ```fullchain.pem```you can create one using ```openssl```

These are the commands to generate a private key and a corresponding  ```fullchain.pem```

```bash
openssl genrsa > privkey.pem
openssl req -new -x509 -key privkey.pem > fullchain.pem

```

To confirm the contents of the ```fullchain.pem``` file:

```bash
openssl x509 -in fullchain.pem -text -noout
```

Generate the digest

```bash
 openssl dgst -sha256 fullchain.pem 
 SHA2-256(fullchain.pem)= 75d0dc6acdfdbe328c359e5ac64058b137733e482a87b3651b990f97c01736d2
```

The SHA256 is returned

```bash
 SHA2-256(fullchain.pem)= 75d0dc6acdfdbe328c359e5ac64058b137733e482a87b3651b990f97c01736d2
```

Create the corresponding TSLA Reccords

```bash
_did.example.com. IN TLSA 3 0 1 b0f4063808926b9db1683694c96138d5afaefac027e82833f0c13f1dd6548834
_443._tcp.example.com. IN TLSA 3 0 1 b0f4063808926b9db1683694c96138d5afaefac027e82833f0c13f1dd6548834
```

### STEP 5B: Add in other certificates and public keys as required

You can add in other certificates and public keys as required. You can use the CERT record type for supported certificate type and TXT to specify unsupported types,

#### Adding in an unsupported public key type

Many ecosystems use the SECP256K1 32 byte hex string format for a public key, and newer signature algorithns such a ECDSA or SCHNORR

You can add in other certificates or public keys. In this example a 32byte hex string representing a SECP256K1 public key. This can be specified  as a TXT record, as below

```bash
_pubkey:example.com. IN TXT "038978f54fe42464f4c03a187e3595cf8fb50abd4ef9b65540d224cb16eb0e68e7"
```

## STEP 6: Confirm Zone File

When you are finished, your modified zone file should look something like this:

```bash
$TTL 3600      ; Default time-to-live value
@       IN      SOA     ns1.example.com. admin.example.com. (
                        2022010101      ; Serial
                        3600            ; Refresh
                        1800            ; Retry
                        604800          ; Expire
                        86400 )         ; Negative Cache TTL



; Name Server records
@       IN      NS      ns1.example.com.
@       IN      NS      ns2.example.com.

; A records for name servers
ns1     IN      A       192.0.2.1
ns2     IN      A       192.0.2.2

; A record for the domain
@       IN      A       192.0.2.100

; Additional records
www     IN      A       192.0.2.100
mail    IN      A       192.0.2.101
@       IN      MX 10   mail.example.com.

; ------ MODIFICATIONS FOR HIGH ASSURANCE DID:WEB
; KSK and ZSK records for signing keys
example.com. IN DNSKEY 257 3 13 +OynQobO0PGvRvpQaRpkQCuMpiljGsc+9BMW3TecfO+sf+D104WLVNcj GThOlYak3c9sqqGYRX150IAlVa5TIg==
example.com. IN DNSKEY 256 3 13 d8nDfDdYzu0UXLC6jQhyiN1FavbdMLtFTq9vJRafQfKggltWGV+SFlVD I79/CQiEDvmsCRCJvjPN1W4gS3ZuxA==
; URI record for DID
_did.example.com. IN URI 0 0 "did:web:example.com"
; TLSA, CERT and TXT records for other certificates and public keys used for signing DID docs
_did.example.com.	IN TLSA 3 0 1 b0f4063808926b9db1683694c96138d5afaefac027e82833f0c13f1dd6548834	
_443._tcp.example.com. 	IN TLSA 3 0 1 b0f4063808926b9db1683694c96138d5afaefac027e82833f0c13f1dd6548834
_did:example.com. IN TXT "a=SECP256K1 s=ECDSA p=038978f54fe42464f4c03a187e3595cf8fb50abd4ef9b65540d224cb16eb0e68e7"

```

## STEP 7: Sign Zone File

```bash
dnssec-signzone -o example.com -f signed.example.com.zone example-mod.com.zone
```

If everything went well, you will see this message

```bash
Verifying the zone using the following algorithms:
- ECDSAP256SHA256
Zone fully signed:
Algorithm: ECDSAP256SHA256: KSKs: 1 active, 0 stand-by, 0 revoked
                            ZSKs: 1 active, 0 stand-by, 0 revoked


signed.example.com.zone
```

The resulting file ```signed.example.com.zone``` should look like below. This is the file that needs to be deployed to the DNS registrar

The resulting file should look like this: [signed zone file](./signed.example.com.zone)

## Step 8: Deploy Zone File to your DNSSEC Provider

Details to come.
