---
title: "TODO - Your title"
abbrev: "TODO - Abbreviation"
category: info

docname: draft-ietf-high-assurance-dids-with-dns-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
# area: AREA
# workgroup: WG Working Group
keyword:
 - next generation
 - unicorn
 - sparkling distributed ledger
venue:
#  group: WG
#  type: Working Group
#  mail: WG@example.com
#  arch: https://example.com/WG
  github: "CIRALabs/high-assurance-did-web"
  latest: "https://CIRALabs.github.io/high-assurance-did-web/draft-carter-high-assurance-did-web.html"

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

This document outlines a method for improving the authenticity, discoverability, and portability of Decentralized Identifiers (DIDs) by utilizing the current DNS infrastructure and its technologies. This method offers a straightforward procedure for a verifier to cryptographically authenticate a DID using data stored in the DNS, separate from the DID document.

--- middle

# Introduction

In the ever-evolving digital world, the need for secure and verifiable identities is paramount. DIDs have emerged as a promising solution, providing a globally unique, persistent identifier that does not require a centralized registration authority. However, like any technology, DIDs face challenges in terms of authenticity, discoverability, and portability.

This is where the Domain Name System (DNS), a well-established and globally distributed internet directory service, comes into play. By leveraging the existing DNS infrastructure, we can enhance the verification process of DIDs. Specifically, we can use Transport Layer Security Authentication (TLSA) and Uniform Resource Identifier (URI) DNS records to add an additional layer of verification.

TLSA records in DNS allow us to associate a certificate or public key with the domain name where the record is found, thus providing a form of certificate pinning. URI records, on the other hand, provide a way to publish mappings from hostnames to URIs, such as DIDs.

By storing crucial information about a DID, such as the DID itself and its Public Key Infrastructure (PKI), in these DNS records, we can provide a verifier with a simple yet effective method to cryptographically verify a DID. This not only ensures the authenticity of the DID document but also allows for it interaction with material signed by the DID without access to the DID document itself.

In essence, the integration of DIDs with DNS, specifically through the use of TLSA and URI records, provides a robust solution to some of the challenges faced by DIDs, paving the way for a more secure and trustworthy digital identity landscape.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Securing a DID using the DNS

The DNS can provide an additional layer of authenticity to a DID by acting as a form of MFA. By hosting important information about a DID, specifically the DID itself (through a URI record) and its PKI (through TLSA records), in a seperate location than the DID document, a user is provided with a higher level of assurance and verifiability that the DID document they are interacting with is authentic while also having a means to verify the DID outside the DID document itself.

+----------------+     +----------------+
|                |     |                |
|    DNS Server  |     |   Web Server   |
|                |     |                |
|    +------+    |     |    +------+    |
|    |  DID  |<--+-----+-->|  DID  |    |
|    +------+    |     |    +------+    |
|                |     |                |
+----------------+     +----------------+

The DNS Server and Web Server represent two separate sets of infrastructure, repudiating the same information. Much in the same way MFA and 2FA work to increase the assurance that a user is who they say they are, the same principle can also be applied to DIDs.

## Specifically for did:web

With did:web, there’s an inherent link between the DNS needed to resolve the associated DID document and the domain where the relevant supporting DNS records are located. This means that the domain specified by the did:web identifier (for example, did:web:**example.ca**) is also the location where you can find the supporting DNS records.

## Other DID methods

In the case of other DID methods, the association between a DID and a DNS domain is still possible although less obvious than with the aformentioned did:web. The W3C DID Core spec supports multiple ways of creating the association between a DID to a domain. This is most intuitively accomplished using one of two different fields.

**alsoKnownAs**: The assertion that two or more DIDs (or other types of URI, such as a domain name) refer to the same DID subject can be made using the {{alsoKnownAs}} property.

**Services**: Alternatively, {{services}} are used in DID documents to express ways of communicating with the DID subject or associated entities. In this case we are referring specifically to the "LinkedDomains" service type.

## DIDs with URI records

However, this association stemming only from the DID is unidirectional. By leveraging URI records as outlined in {{DID-in-the-DNS}}, we can create a bidirectional relationship, allowing a domain to publish their associated DIDs in the DNS.

***Ex: _did.example-issuer.ca IN URI 1 0 “did:example:XXXXXXX”***

This relationship enhances security, as an entity would require control over both the DID and the domain’s DNS server to create this bidirectional association, reducing the likelihood of malicious impersonation.

The ability for an organization to publish a list of their DIDs on the DNS is also beneficial as it establishes a link between the DNS, which is ubiquitously supported, and the distributed ledger (or other places) where the DID document resides on which may not have the same degree of access or support, enhancing discoverability.

### URI record scoping

- The records MUST be scoped by setting the global underscore name of the URI RRset to *_did* (0x5F 0x64 0x69 0x64).

### Issuer Handles

An issuer may have multiple sub entities issuing credentials on their behalf, such as the different faculties in a university issuing diplomas. Each of these entities may have one or more DIDs of their own. For this reason, the introduction of an issuer handle, represented as a subdomain in the resource record name, provides a simple way to facilitate the distinction of DIDs, their public keys, and credentials they issue in their relationship to the issuer.

***Ex: _did.diplomas.university-issuer.ca IN URI 1 0 “did:example:XXXXXXX”***

***Ex: _did.certificates.university-issuer.ca IN URI 1 0 “did:example:XXXXXXX”***

## PKI with TLSA records

The DID to DNS mapping illustrated in section 4 provides a way of showing the association between a DID and a domain, but no way of verifying that relationship. By hosting the public keys of that DID in its related domain’s zone, we can provide a cryptographic linkage to bolster this relationship while also providing access to the DID’s public keys outside of the infrastructure where the DID document resides, facilitating interoperability. If a verifier is presented with a credential issued or signed by a DID using a method they do not support, they would have the option to perform the cryptographic verification of the credential's signature using the public key stored in the DNS.

TLSA records {{!RFC6698}} provide a simple way of hosting cryptographic information in the DNS.

### TLSA Record Scoping, Selector Field

When public keys related to DIDs are published in the DNS as TLSA records:

- The records MUST be scoped by setting the global underscore name of the TLSA RRset to *_did* (0x5F 0x64 0x69 0x64).
- The Selector Field of the TLSA record must be set to 1, SubjectPublicKeyInfo: DER-encoded binary structure as defined in {{!RFC5280}}.

### Issuer Handles

As mentioned in section 4.2, an issuer may have multiple sub entities issuing credentials on their behalf, likely with their own set or sets of keypairs. Because these keypairs will need to be represented in the DNS as TLSA records, the use of an issuer handle as outlined in section 4.2 will facilitate the distinction of the different public keys in their relation to the issuer.

***Ex: _did.diplomas.university-issuer.ca IN TLSA 3 1 0 “4e18ac22c00fb9...b96270a7b2”***

***Ex: _did.certificates.university-issuer.ca IN TLSA 3 1 0 “4e18ac22c00fb9...b96270a7b3”***

### Instances of Multiple DIDs

It is also likely an issuer may be using or wish to associate multiple DIDs with a single domain or subdomain. In this case it is possible to expand the name of the RRset using both the related DID method and identifier to more clearly associate the public key and its corresponding DID. In this circumstance, we propose using another 2 additional sub names, the first following the _did global identifier denoting the method, and the second denoting the DID's id.

***Ex: _did.example.123abc.university-issuer.ca IN TLSA 3 1 0 “4e18ac22c00fb9...b96270a7b2”***

***Ex: _did.example2.123abc.university-issuer.ca IN TLSA 3 1 0 “4e18ac22c00fb9...b96270a7b3”***

### Instances of Multiple Key Pairs

Depending on the needs of the issuer, it is possible they may use multiple keypairs associated with a single DID to sign and issue credentials. In this case a mechanism to differentiate which verificationMethod the public key is related to will need to be added to the name of the TLSA RRset.

A simple solution would be to create a standardized naming convention by expanding the RRset name using the fragment of the target verificationMethod's ID.

***Ex: _did.key-1.example-issuer.ca IN TLSA 3 1 0 "4e18ac22c00fb9...b96270a7b4"***

***Ex: _did.key-1.example.123abc.example-issuer.ca in TLSA 3 1 0 “4e18ac22c00fb9...b96270a7b5”***

***Ex: _did.key-2.example.123abc.example-issuer.ca in TLSA 3 1 0 “4e18ac22c00fb9...b96270a7b5”***

### Benefits of Public Keys in the DNS

Hosting the public keys in TLSA records provides a stronger mechanism for the verifier to verify the issuer with, as they are able to perform a cryptographic challenge against the DID using the corresponding TLSA records, or against the domain using the corresponding {{verificationMethod}} in the DID document. The accessibility of the public keys is also beneficial, as the verifier does not need to resolve the DID document using a did method they do not support to access the key material. This limits the burden of having to interoperate with a multitude of different did methods and for credential verification, facilitating interoperability and adoption.

# Role of DNSSEC for Assurance and Revocation

It is hihgly recommended that all the participants in this digital identity ecosystem enable DNSSEC signing for the DNS instances they operate. See {{!RFC9364}}.

DNSSEC provides cryptographic assurance that the DNS records returned in response to a query are authentic and have not been tampered with. This assurance within the context of the *_did* URI and *_did* TLSA records provides another mechanism to ensure the integrity of the DID and its public keys outside of infrastructure it resides on directly from the domain of its owner.

Within this use-case, DNSSEC also provides revocation checks for both DIDs and public keys. In particular, a DNS query for a specific *_did* URI record or *_did* TLSA record can return an NXDOMAIN {{!RFC8020}} response if the DID or public key has been revoked. This approach can simplify the process of verifying the current validity of DIDs and public keys by reducing the need for complex revocation mechanisms or implementation specific technologies.

# Digital Signature and Proof Value of the DID Document

Digital signatures ensure the integrity of the DID Document, and by extent the public keys, authentication protocols, and service endpoints necessary for initiating trustworthy interactions with the identified entity. The use of digital signatures in this context provides a robust mechanism for verifying that the DID Document has not been tampered with and indeed originates from the correct entity.

In accordance with W3C specifications, we propose including a data integrity proof such as those outlined in {{dataIntegrityProofECDSA}} and {{dataIntegrityProofEdDSA}}.

```javascript
"proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "ecdsa-jfc-2019",
    "created": "2023-10-11T15:27:27Z",
    "verificationMethod": "did:web:trustregistry.ca#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "2VszW6oinTqBaSbz9oAfh6tAmYsc57smCr1nSirGucB1XA8VjcGTcUXfLZbnTyppnJibhr7pMzEmUFELxFqdWKH9"
  }
```

The data integrety proof SHOULD be signed using a verificationMethod that has an associated TLSA record to allow for the verification of the data integrity proof using data contained outside of the DID document. This provides an added layer of authenticity, as the information contained in the DID document would need to be supported accross 2 different domains.

## Inclusion of a TTL

To accompany the proof value, a TTL (the same as the TTL of DNS resource records) should also be included, indicating to a resolver how long it should cache a given DID document. The value of the "timeToLive" field is an integer corresponding to the number of seconds the current DID document should be cached for.

```javascript
"timeToLive": 86400
```

Including a TTL would increase performance, as resolvers wouldn't need to query for a DID document each time they wanted to resolve it, instead being able to cache it for a set amount of time.

It would also provide a strong mechanism for insuring the information of the DID document is up to date, as a shorter or longer TTL could be used depending on the use case.

# Verification Process

Using the new DNS records and proof object in the DID document, we can enable a more secure and higher assurance verification process for the DID. It is important to note that while not strictly necessary, DNSSEC verification should be performed each time a DNS record is resolved to ensure accuracy.

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
3. **Verification of the PKI:** With the claimed association between the DID and the domain verified, the user would then proceed to verify the key material between the DID and the domain.
   1. The user would query for a TLSA record. Depending on the record/s returned, the user would verify either the hash of the verificationMethod or verificationMethod itself matches what was returned by the TLSA record content.
      1. Note: This may require some conversion, as TLSA records store key material as hex encoded DER format, and this representation is not supported by verificationMethods. However, there are many well supported cryptography libraries in a variety of languages that facilitate the conversion process.
4. **Verification of the DID document's integrity:** After verifying that the did's key material matches what is represented in the TLSA records of the associated domain, the user would then verify the "proof" object to ensure the integrity of the DID document.
   1. This can be accomplished by using either the verificationMethod directly from the did document, or using the key material stored in the TLSA record. Using the TLSA record would provide a higher level of assurance as this confirms the key material is being accurately represented accross 2 different domains, both at the DID document level and the DNS level.
   2. As mentioned above, if using the TLSA record, some conversion will be necessary to convert the DER format public key to whatever is required by the proof's cryptosuite.

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
