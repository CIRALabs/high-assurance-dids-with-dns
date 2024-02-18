# Steps to Create a Subdomain

A technical prototype has been developed to demonstrate the did doc verification process. In short the following steps are undertaken:

1. Retrieve DID doc, check to see if valid format
2. Determine from header the appropriate signature verification process. (3 are currently defined for the prototype)
3. Check to see if website TLS public key is same as what is registered for the domain.
4. Look up public key in DNS (either as TLSA or TXT record).
5. Verify DID doc using signature and looked up public key.
6. Check to see if DID doc has not expired (< TTL).
7. Return True if all checks passed, otherwise False if there is a failure on any test above

## Setting up subdomain for reverve proxy

- Create subdomain on reverse proxy server (nginx) with service directive to forward to running instance.
- Create symbolic link of server directive to ```sites-enabled```
- Test subdomain with ```nginx -t```
- Restart nginx ```sudo systemctl restart nginx```
- Using your DNSSEC provider add a corresponding DNS A subdomain record poing to running instance ip address
- On your reverse proxy server run ```sudo certbot --nginx -d subdomain.trustroot.ca```
- Confirm that you can see the homepage of htt://subdomain.trustroot.ca

## Configuring the Server

- In the ```data/keys``` directory create a subdirectory for the fully-qualified domain name, for example ```mkdir subdomain.trustroot.ca```. Change into this directory.
- Run the following commands in sequence, ensuring following the prompts and ensuring you have entered the fully qualified doman name

```bash
openssl ecparam -name prime256v1 -genkey -out privkey.pem
openssl req -new -key privkey.pem -out csr.pem
openssl req -x509 -sha256 -days 365 -key privkey.pem -in csr.pem -out certificate.pem

```

- Upon completion you should have the following files: ```certificate.pem  csr.pem  privkey.pem```
- add corresponding subdomain record in the ```data\issuers.json``` file. Ensure ```dnsType:"tlsa"``` so that the right key files are used.

## Configuring DNS records

### TLSA of website certificate

- The first step is to add a TLSA record that corresponds to the website certificate generated earlier. You should be able to find it in the server directive file update by certbot. It should look something like this: ```/etc/letsencrypt/live/subdomain.trustroot.ca/fullchain.pem```. cat this file and copy into clipboard. Likely it will consist of three certificates. Be sure to select all for copying.
- Go to [SSL Tools](https://ssl-tools.net/tlsa-generator) to generate the record. Select Usage:DANE-EE, Selector:Use Subject public key, Matching Type: Full - No Hash
- for domain: add in the fully qualified domain
- Paste the copied certificate contents into the textbox and click generate
- the corresponding record should look like this: ```_443._tcp.subdomain.trustroot.ca. IN TLSA 3 1 0 30593...c3b3e```
- do the same for your ```certificate.pem``` file to create a record like: ```_did.subdomain.trustroot.ca. IN TLSA 3 1 0 30593...c3b3e```


