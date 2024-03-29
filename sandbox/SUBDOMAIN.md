# Steps to Create a Trust Root Subdomain

## Introduction

A technical prototype has been developed to demonstrate the did doc verification process as part of a trusted root domain.

### Prototype

Prototype is live at:

- [trustroot.ca](https://trustroot.ca)
- [credentials.trustroot.ca](https://credentials.trustroot.ca)
- [community.trustroot.ca](https://community.trustroot.ca)

### W3C Conformance

- DID doc proofs are conformant to [W3C Recommendation Draft: Verifiable Credential Data Integrity 1.0](https://www.w3.org/TR/vc-data-integrity/)

### Independent Verification

A python script has been developed to test independent verification [here](./scripts/verify_did.py)

The following checks are carried out for a high assurance did:web

1. Retrieve DID doc, check to see if valid format
2. Determine from proof object the appropriate signature verification process. (3 are currently defined for the prototype)
3. Check DNSSEC TLSA record if website TLS public key is same as what was registered for the website domain. (or DNS TXT record if DNSSEC is unavailable)
4. Look up public key in DNSSEC TLSA record. (or DNS TXT record if DNSSEC is unavailabe)
5. Verify DID doc using signature and public key found in DNSSEC TLSA record. (or DNS TXT record in DNSSEC is unavailabe)
6. Check to see if DID doc has not expired (< TTL).
7. Return ```HighAssurance = True`` if all checks passed, otherwise False if there is a failure on any test above

Note: If some of the checks fail or have to fall back to DNS (Steps 3,4 and 4), that means it can be relied on as a lower assurance did:web.  Only Step 5 (signature verification) needs to pass to be still be relied on at a lower level of assurance subject to the discretion of the relying party.

## Setting up a trust root subdomain

### Setting up subdomain for reverse proxy

- Create subdomain on reverse proxy server (nginx) with service directive to forward to running instance.
- Create symbolic link of server directive to ```sites-enabled```
- Test subdomain with ```nginx -t```
- Restart nginx ```sudo systemctl restart nginx```
- Using your DNSSEC provider add a corresponding DNS A subdomain record poing to running instance ip address
- On your reverse proxy server run ```sudo certbot --nginx -d subdomain.trustroot.ca```
- Confirm that you can see the homepage of htt://subdomain.trustroot.ca

### Configuring the Technical Prototype Server

- In the ```data/keys``` directory create a subdirectory for the fully-qualified domain name, for example ```mkdir subdomain.trustroot.ca```. Change into this directory.
- Run the following commands in sequence, ensuring following the prompts and ensuring you have entered the fully qualified doman name

```bash
openssl ecparam -name prime256v1 -genkey -out privkey.pem
openssl req -new -key privkey.pem -out csr.pem
openssl req -x509 -sha256 -days 365 -key privkey.pem -in csr.pem -out certificate.pem

```

- Upon completion you should have the following files: ```certificate.pem  csr.pem  privkey.pem```
- add corresponding subdomain record in the ```data\issuers.json``` file. Ensure ```dnsType:"tlsa"``` so that the right key files are used.

## Configuring DNSSEC records

### TLSA of website certificate

- The first step is to add a TLSA record that corresponds to the website certificate generated earlier. You should be able to find it in the server directive file update by certbot. It should look something like this: ```/etc/letsencrypt/live/subdomain.trustroot.ca/fullchain.pem```. cat this file and copy into clipboard. Likely it will consist of three certificates. Be sure to select all for copying.
- Go to [SSL Tools](https://ssl-tools.net/tlsa-generator) to generate the record. Select Usage:DANE-EE, Selector:Use Subject public key, Matching Type: Full - No Hash
- for domain: add in the fully qualified domain
- Paste the copied certificate contents into the textbox and click generate
- the corresponding record should look like this: ```_443._tcp.subdomain.trustroot.ca. IN TLSA 3 1 0 30593...c3b3e```


### TLSA for DID doc

Follow the same processs as above for your trust root domain  ```certificate.pem``` file to create a record like: ```_did.subdomain.trustroot.ca. IN TLSA 3 1 0 30593...c3b3e```

### X509 certificates for user dids

The technical prototype now supports x509 certificates for user dids. The steps to create a x509 user cert are as follows:

- create subdirectory in ```data/keys/users/``` that corresponds to the username e.g., ```/data/keys/users/examplecorp```
- cd to the sudirectory and run the following commands (yes, the are same commands as for the issuers)

```bash
openssl ecparam -name prime256v1 -genkey -out privkey.pem
openssl req -new -key privkey.pem -out csr.pem
openssl req -x509 -sha256 -days 365 -key privkey.pem -in csr.pem -out certificate.pem
```

- when you are done, you should have these three files: ```certificate.pem  csr.pem  privkey.pem```

- modify the ```/data/user.json``` file to have the following corresponding entry:

```bash
{"user": "examplecorp", "pubkey":"x509" },
```

- restart the service so changes can take effect