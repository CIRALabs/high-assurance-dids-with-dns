---
title: "High Assurance DIDs with DNS"
abbrev: "hiadid"
category: info

docname: draft-carter-high-assurance-dids-with-dns-latest
submissiontype: independent
number:
date:
v: 3
keyword:
 - next generation
 - unicorn
 - sparkling distributed ledger
venue:
  github: "CIRALabs/high-assurance-dids-with-dns"
  latest: "https://ciralabs.github.io/high-assurance-dids-with-dns/draft-carter-high-assurance-dids-with-dns.html"

author:
-
   ins: J. Carter
   name: Jesse Carter
   org: CIRA
   email: jesse.carter@cira.ca
-
   ins: J. Latour
   name: Jacques Latour
   org: CIRA
   email: jacques.latour@cira.ca
-
   ins: M. Glaude
   name: Mathieu Glaude
   org: NorthernBlock
   email: mathieu@northernblock.io
-
   ins: T. Bouma
   name: Tim Bouma
   org: Digital Governance Council
   email: tim.bouma@dgc-cgn.org

informative:
   Self-Sovereign-Identity:
      title: "Self-Sovereign Identity"
      author:
        -
          ins: D. Reed
          name: Drummond Reed
        -
          ins: A. Preukschat
          name: Alex Preukschat
      seriesinfo:
         ISBN: 9781617296598
      date: 2021

normative:
   DID-Specification-Registries:
      title: "DID Specification Registries"
      target: https://www.w3.org/TR/did-spec-registries/#did-methods
   W3C-VC-Data-Model:
      title: "Verifiable Credentials Data Model v1.1"
      target: https://www.w3.org/TR/vc-data-model/
   alsoKnownAs:
      title: "Decentralized Identifiers (DIDs) v1.0"
      target: https://www.w3.org/TR/did-core/#also-known-as
   services:
      title: "Decentralized Identifiers (DIDs) v1.0"
      target: https://www.w3.org/TR/did-core/#services
   LinkedDomains:
      title: "Well Known DID Configuration"
      target: https://identity.foundation/.well-known/resources/did-configuration/#linked-domain-service-endpoint
   DID-in-the-DNS:
      title: "The Decentralized Identifier (DID) in the DNS"
      target: https://datatracker.ietf.org/doc/html/draft-mayrhofer-did-dns-05#section-2
   verificationMethod:
      title: "Decentralized Identifiers (DIDs) v1.0"
      target: https://www.w3.org/TR/did-core/#verification-methods
   issuer:
      title: "Verifiable Credentials Data Model v2.0"
      target: https://www.w3.org/TR/vc-data-model-2.0/#issuer
   dataIntegrityProofECDSA:
      title: "Data Integrity ECDSA Cryptosuites v1.0"
      target: https://www.w3.org/TR/vc-di-ecdsa/#proof-representations
   dataIntegrityProofEdDSA:
      title: "Data Integrity ECDSA Cryptosuites v1.0"
      target: https://www.w3.org/TR/vc-di-eddsa/#proof-representations

--- abstract

This document outlines a method for improving the authenticity, discoverability, and portability of Decentralized Identifiers (DIDs) by utilizing the current DNS infrastructure and its technologies. This method offers a straightforward procedure for a verifier to cryptographically cross-validate a DID using data stored in the DNS, separate from the DID document.

--- middle

# Introduction

In the ever-evolving digital world, the need for secure and verifiable identities is paramount. DIDs have emerged as a promising solution, providing a globally unique, persistent identifier that does not require a centralized registration authority. However, like any technology, DIDs face challenges in terms of authenticity, discoverability, and portability.

This is where the Domain Name System (DNS), a well-established and globally distributed internet directory service, comes into play. By leveraging the existing DNS infrastructure, we can enhance the verification process of DIDs. Specifically, we can use Transport Layer Security Authentication (TLSA) and Uniform Resource Identifier (URI) DNS records to add an additional layer of verification and authenticity to DIDs.

TLSA records in DNS allow us to associate a certificate or public key with the domain name where the record is found, thus providing a form of certificate pinning. URI records, on the other hand, provide a way to publish mappings from hostnames to URIs, such as DIDs.

By storing crucial information about a DID, such as the DID itself and its Public Key Infrastructure (PKI) in these DNS records, we can provide a verifier with a simple yet effective method to cross-validate and authenticate a DID. This not only ensures the authenticity of the DID document but also allows for interaction with material signed by the DID without access to the DID document itself.

In essence, the integration of DIDs with DNS, specifically through the use of TLSA and URI records, provides a robust solution to some of the challenges faced by DIDs, paving the way for a more secure and trustworthy digital identity landscape.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Securing a DID using the DNS

Much like presenting two pieces of ID to provide a higher level of assurance when proving your identity or age, replicating important information about a DID into a different domain (like the DNS) enables a similar form of cross validation. This enhances the initial trust establishment between the user and the DID document, as the key information can be compared and verified across two segregated sets of infrastructure. This also acts as a form of ownership verification in a similar way to 2FA, as the implementer must have control over both the DNS zone and the DID document to properly duplicate the relevant information.

    +----------------+     +----------------+
    |                |     |                |
    |   DNS Server   |     |   Web Server   |
    |                |     |                |
    |   +-------+    |     |   +-------+    |
    |   |  DID  |<---+-----+-->|  DID  |    |
    |   +-------+    |     |   +-------+    |
    |   +-------+    |     |   +-------+    |
    |   |  PKI  |<---+-----+-->|  PKI  |    |
    |   +-------+    |     |   +-------+    |
    |                |     |                |
    +----------------+     +----------------+

The diagram above illustrates how a web server storing the DID document, and the DNS server storing the URI and TLSA records shares and links the key information about the DID accross two independant sets of infrastructure.

## Specifically for did:web

With did:web, there’s an inherent link between the DNS needed to resolve the associated DID document and the domain where the relevant supporting DNS records are located. This means that the domain specified by the did:web identifier (for example, did:web:**example.ca**) is also the location where you can find the supporting DNS records.

## Other DID methods

In the case of other DID methods, the association between a DID and a DNS domain is still possible although less obvious than with the aformentioned did:web. The W3C DID Core spec supports multiple ways of creating the association between a DID to a domain. This is most intuitively accomplished using one of two different fields.

**alsoKnownAs**: The assertion that two or more DIDs (or other types of URI, such as a domain name) refer to the same DID subject can be made using the {{alsoKnownAs}} property.

**Services**: Alternatively, {{services}} are used in DID documents to express ways of communicating with the DID subject or associated entities. In this case we are referring specifically to the {{LinkedDomains}} service type.

## DIDs with URI records

However, this association stemming only from the DID is unidirectional. By leveraging URI records as outlined in {{DID-in-the-DNS}}, we can create a bidirectional relationship, allowing a domain to publish their associated DIDs in the DNS.

***Ex: _did.example-issuer.ca IN URI 1 0 “did:example:XXXXXXX”***

This relationship enhances security, as an entity would require control over both the DID and the domain’s DNS server to create this bidirectional association, reducing the likelihood of malicious impersonation.

The ability for an organization to publish a list of their DIDs on the DNS is also beneficial as it establishes a link between the DNS, which is ubiquitously supported, and the distributed ledger (or other places) where the DID document resides on which may not have the same degree of access or support, enhancing discoverability.

### URI record scoping

- The records MUST be scoped by setting the global underscore name of the URI RRset to *_did* (0x5F 0x64 0x69 0x64).

### Issuer Handles

An issuer may have multiple sub entities issuing credentials on their behalf, such as the different faculties in a university issuing diplomas. Each of these entities may have one or more DIDs of their own. For this reason, the introduction of an issuer handle, represented as a subdomain in the resource record name, provides a simple way to facilitate the distinction of DIDs, their public keys, and credentials they issue in their relationship to an issuer or root authority.

***Ex: _did.diplomas.example-issuer.ca IN URI 1 0 “did:example:XXXXXXX”***

***Ex: _did.certificates.example-issuer.ca IN URI 1 0 “did:example:XXXXXXX”***

## PKI with TLSA records

The DID to DNS mapping illustrated in section 4 provides a way of showing the association between a DID and a domain, but no way of verifying that relationship. By hosting the public keys of that DID in its related domain’s zone, we can provide a cryptographic linkage to bolster this relationship while also providing access to the DID’s public keys outside of the infrastructure where the DID document itself resides, facilitating interoperability. If a verifier is presented with a credential issued or signed by a DID using a method they do not support, they would have the option to perform the cryptographic verification of the credential's signature using the public key stored in the DNS.

TLSA records {{!RFC6698}} provide a simple way of hosting cryptographic information in the DNS.

### TLSA Record Scoping, Selector Field

When public keys related to DIDs are published in the DNS as TLSA records:

- The records MUST be scoped by setting the global underscore name of the TLSA RRset to *_did* (0x5F 0x64 0x69 0x64).
- The Selector Field of the TLSA record must be set to 1, SubjectPublicKeyInfo: DER-encoded binary structure as defined in {{!RFC5280}}.

### Issuer Handles

As mentioned in section 4.2, an issuer may have multiple sub entities issuing credentials on their behalf, likely with their own set or sets of keypairs. Because these keypairs will need to be represented in the DNS as TLSA records, the use of an issuer handle as outlined in section 4.2 will facilitate the distinction of the different public keys in their relation to the issuer.

***Ex: _did.diplomas.example-issuer.ca IN TLSA 3 1 0 “4e18ac22c00fb9...b96270a7b2”***

***Ex: _did.certificates.example-issuer.ca IN TLSA 3 1 0 “4e18ac22c00fb9...b96270a7b3”***

### Instances of Multiple DIDs

It is also likely an issuer may be using or wish to associate multiple DIDs with a single domain or subdomain. In this case it is possible to expand the name of the RRset using both the related DID method and identifier to more clearly associate the public key and its corresponding DID. In this circumstance, we propose using another 2 additional sub names, the first following the _did global identifier denoting the method, and the second denoting the DID's id.

***Ex: _did.example.123abc.example-issuer.ca IN TLSA 3 1 0 “4e18ac22c00fb9...b96270a7b2”***

***Ex: _did.example2.456abc.example-issuer.ca IN TLSA 3 1 0 “4e18ac22c00fb9...b96270a7b3”***

### Instances of Multiple Key Pairs

Depending on the needs of the issuer, it is possible they may use multiple keypairs associated with a single DID to sign and issue credentials. In this case, a TLSA record will be created per {{verificationMethod}} and then be bundled into the corresponding TLSA RRset. A resolver can then parse the returned records and match the key content to the verificationMethod they wish to interact with or verify.

***Ex: _did.example-issuer.ca IN TLSA 3 1 0 "4e18ac22c00fb9...b96270a7b4"***

***Ex: _did.example-issuer.ca IN TLSA 3 1 0 "5f29bd33d11gc1...b96270a7b5"***

### Benefits of Public Keys in the DNS

Hosting the public keys in TLSA records provides a stronger mechanism for the verifier to verify the issuer with, as they are able to perform a cryptographic challenge against the DID using the corresponding TLSA records, or against the domain using the corresponding {{verificationMethod}} in the DID document. The accessibility of the public keys is also beneficial, as the verifier does not need to resolve the DID document using a did method they do not support to access the key material. This limits the burden of having to interoperate with a multitude of different did methods and for credential verification, facilitating interoperability and adoption.

# Role of DNSSEC for Assurance and Revocation

It is RECOMMENDED that all the participants in this digital identity ecosystem enable DNSSEC signing for the DNS instances they operate. See {{!RFC9364}}.

DNSSEC provides cryptographic assurance that the DNS records returned in response to a query are authentic and have not been tampered with. This assurance within the context of the *_did* URI and *_did* TLSA records provides another mechanism to ensure the integrity of the DID and its public keys outside of infrastructure it resides on directly from the domain of its owner.

Within this use-case, DNSSEC also provides revocation checks for both DIDs and public keys. In particular, a DNS query for a specific *_did* URI record or *_did* TLSA record can return an NXDOMAIN {{!RFC8020}} response if the DID or public key has been revoked. This approach can simplify the process of verifying the current validity of DIDs and public keys by reducing the need for complex revocation mechanisms or implementation specific technologies.

# Digital Signature and Proof Value of the DID Document

Digital signatures ensure the integrity of the DID Document, and by extent the public keys, authentication protocols, and service endpoints necessary for initiating trustworthy interactions with the identified entity. The use of digital signatures in this context provides a robust mechanism for verifying that the DID Document has not been tampered with and indeed originates from the correct entity.

In accordance with W3C specifications, we propose including a data integrity proof such as those outlined in {{dataIntegrityProofECDSA}} and {{dataIntegrityProofEdDSA}}, with the mandatory inclusions of the "created" and "expiry" fields. The inclusion of which acts as a lifespan for the document, similar to the TTL for a DNS record. Depending on the use case and security requirement, a longer or shorter expiry period would be used as necessary.

```javascript
"proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "ecdsa-jfc-2019",
    "created": "2023-10-11T15:27:27Z",
    "expires": "2099-10-11T15:27:27Z",
    "proofPurpose": "authentication",
    "verificationMethod": "did:web:trustregistry.ca#key-1",
  }
```

The data integrity proof SHOULD be signed using a verificationMethod that has an associated TLSA record to allow for the verification of the data integrity proof using data contained outside of the DID document. This provides an added layer of authenticity, as the information contained in the DID document would need to be supported accross 2 different domains.

# Verification Process

Using the new DNS records and proof object in the DID document, we enable a more secure and higher assurance verification process for the DID. It is important to note that while not strictly necessary, DNSSEC verification should be performed each time a DNS record is resolved to ensure their authenticity.

1. **Initial presentation:** The user is presented with a DID document, ex. did:web:example.ca.
2. **Verification of the DID:** The user verifies the DID is represented as a URI record in the associated domain.
   1. In the case of did:web, the domain to be queried is indicated by the last segment of the did. ex. **did:web:example.ca -> _did.example.ca**
   2. In the case of other did methods, the domain to be queried is indicated by the value held in the "alsoKnownAs" or "service" fields.
      1. ex.
      ```javascript
      {"alsoKnownAs": "example.ca"} -> _did.example.ca
       ```
      2. ex.
      ```javascript
      {"services": [{
         "id":"did:example:123abc#linked-domain",
         "type": "LinkedDomains",
         "serviceEndpoint": "https://example.ca" -> _did.example.ca
         }]
      }
      ```
3. **Verification of the PKI:** With the association between the DID and the domain verified, the user would then proceed to verify the key material between the DID and the domain.
   1. The user would query for a TLSA record. Depending on the record/s returned, the user would verify either the hash of the verificationMethod or verificationMethod itself matches what was returned by the TLSA record content.
      1. Note: This may require some conversion, as TLSA records store key material as hex encoded DER format, and this representation is not supported by {{verificationMethod}}. However, there are many well supported cryptography libraries in a variety of languages that facilitate the conversion process.
4. **Verification of the DID document's integrity:** After verifying that the did's key material matches what is represented in the TLSA records of the associated domain, the user would then verify the "proof" object to ensure the integrity of the DID document.
   1. This can be accomplished by using either the {{verificationMethod}} directly from the did document, or using the key material stored in the TLSA record. Using the TLSA record would provide a higher level of assurance as this confirms the key material is being accurately represented accross 2 different domains, both at the DID document level and the DNS level.
   2. As mentioned above, if using the TLSA record, some conversion will be necessary to convert the DER format public key to whatever is required by the proof's cryptosuite.

## Verification Failure

If at any given step verification fails, the DID document should be deemed INSECURE. Whether it is due to the DID and DNS being out of sync with recent updates, or the DID document or DNS zone themselves have been compromised, it is highly advised that the user stop interacting with the given DID until verification succeeds and cross-verification is restored.

# Control Requirements

This section defines a simple framework to define a set of technical controls that can be implemented and mapped into levels of assurance for did:web identifiers.

To assist in decision-making and implementation, The controls are ordered in increasing level of security assurance and are grouped into levels of assurance from **LOW-** to **HIGH+**

- **Issuing Authority** is the entity accountable for the did:web identifier.
- **Issuing Service** is the entity responsible for operating the did:web identifier insfrastructure.

In many cases the **Issuing Authority** may delegate elements of providing a high assurance did:web identitifier to an **Issuing Service** that may be a commercial provider.

In the simplest case, the **Issuing Authority** can be regarded as the same as the **Issuing Service**.

Note that Controls 9, 10, and 11 CANNOT BE DELEGATED to an **Issuing Service**

11 technical controls are defined. These controls would be implemented in order of precedence for an increasing level of security assurance. (e.g., Control No. N would need to be implemented before implementing Control No. N+1)

|Control No.|Control Name|Description|
|--|---|---|
|1|DID Resource Control|The Issuing Service MUST control the resource that generates the DID document. (i.e., website)|
|2|DID Document Management|The Issuing Service MUST have the ability to do CRUD operations on the DID document.|
|3|DID Document Data Integrity|The Issuing Service MUST ensure the data integrity of the DID document by cryptographic means, typically a digital signature or other means. The use of approved or established cryptographic algorithmsis HIGHLY RECOMMENDED|
|4|DID Document Key Control|The Issuing Service MUST control the keys required to sign the DID document.|
|5|DID Document Key Generation|With proper delegation from the Issuing Authority, the DID Document signing key MAY be generated by the Issuing Service. Otherwise, the signing key must be generated by the Issuing Authority.|
|6|Domain Zone Control|The Issuing Service MUST have control of the domain zone (or subdomain zone).If direct control of the domain is not feasible, the use of an accredited DNS provider is HIGHLY RECOMMENDED|
|7|Domain Zone Mapping|There MUST be domain zone records that map the necessary URI, TLSA, CERT and/or TXT records to the specified did:web identifier.|
|8|Domain Zone Signing|The domain zone records MUST be signed according to DNSSEC. (RRSIG)|
|9|Domain Zone Signing Key Control|The Issuing Authority MUST have control over the domain zone keys used for signing and delegation. (KSK and ZSK)|
|10|Domain Zone Signing Key Generation|The signing keys MUST be generated under the control of the Issuing Authority.|
|11|Hardware Security Module|A FIPS 140-2 compliant hardware security module must be under the control of the Issuing Authority.|

In addition to the technical controls specificed in the table it is advisable to add in DANE (DNS-based Authentication of Named Entities) {{!RFC6698}} to secure TLS communications. TLS uses certificates to bind keys to names, which are published by public "Certification Authorities" (CAs). It is important to realize that the public CA model is fundamentally vulnerable because it allows any CA to issue a certificate for any domain name. Thus, a compromised CA can issue a fake replacement certificate which could be used to subvert TLS-protected websites. DANE)offers the option to use the DNSSEC infrastructure to store and sign keys and certificates that are used by a TLS-protected website. The keys are bound to names in the Domain Name System (DNS), instead of relying on arbitrary keys and names issued in a potentially compromised certificate.

# Levels of Assurance

Many trust frameworks specify levels of assurance to assist in determing which controls must be implemented.

The following table is not a definitive mapping to trust framework levels of assurance. It is intended to assist in determing mappings by grouping the controls within a range from **LOW-** to **HIGH+** relating to the appropriate risk level. Note that controls are additive in nature. (i.e.,, controls of the preceding level must be fulfilled).

|Level of Assurance|Controls|Description|
|---|---|---|
|**LOW-**| Control 1|SHOULD only be used for low risk transactions where attribution to originator is desireable.|
|**LOW**|Control 2|SHOULD only be used for lower risk transactions where establishing the accountablity of the originator is desirable.|
|**MEDIUM**|Controls 3, 4 and 5|MAY be used for medium risk commercial transactions, such as correspondence, proposals, etc.|
|**MEDIUM+**| Controls 6 and 7|MAY be used for higher risk transcations, such as signing and verifying invoices, contracts, or official/legal docmentation|
|**HIGH**| Controls 8, 9 and 10|MUST be high risk transactions, such as government transactions for signing and verifying licenses, certifications or identification|
|**HIGH+**| Control 11|MUST be used for extremely high risk transactions where there may be systemic or national security implications|

# Security Considerations

TODO Security

# IANA Considerations

Per {{!RFC8552}}, IANA is requested to add the following entries to the
"Underscored and Globally Scoped DNS Node Names" registry:

    +---------+------------+-------------------------------------------+
    | RR Type | _NODE NAME | Reference                                 |
    +---------+------------+-------------------------------------------+
    | TLSA    | _did       | [draft-ietf-high-assurance-dids-with-dns] |
    | URI     | _did       | [draft-mayrhofer-did-dns-01]              |
    +---------+------------+------------------------------------------+.

--- back

# W3C Considerations

1. We propose the inclusion of an optional data integrity proof for the DID document, as outlined in {{dataIntegrityProofECDSA}} and {{dataIntegrityProofEdDSA}}.
2. We propose the inclusion of an optional TTL ("timeToLive") field in the DID document to indicate the amount of time a resolver should cache the document.

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
