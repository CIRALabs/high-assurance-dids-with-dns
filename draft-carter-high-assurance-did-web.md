---
title: "TODO - Your title"
abbrev: "TODO - Abbreviation"
category: info

docname: draft-carter-high-assurance-did-web-latest
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
    fullname: "Jesse"
    organization: Your Organization Here
    email: "43359255+jessecarter111@users.noreply.github.com"

normative:

informative:

--- abstract
A consice and informative abstract :)

This memo describes an implementation for enhanced DID authenticity, discoverability, and portability created by leveraging the existing DNS infrastructure and technologies there in. This implementation provides a verifier with a simple process by which to cryptographically verify a DID using information store outside the DID document in the DNS.

--- middle

# Introduction

A well written introduction :)

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Securing a DID using the DNS

The DNS can provide an additional layer of authenticity to a DID by acting as a form of MFA. By hosting important information about a DID, specifically the DID itself (through a URI record) and its PKI (through TLSA records), in a seperate location then the DID document, a verifier is provided with a higher level of assurance and verifiability that the DID document they are interacting with is authentic while also having a means to verify the DID outside the DID itself.

### Specifically for DID:WEB

 In the case of DID:WEB, there is a natural mapping between the DNS which is required for the resolution of the associated DID document and the domain in which the relevant supporting DNS records can be found. It follows that the domain pointed to by the did:web identifier, ex: did:web:example.ca would also indicate that the supporting DNS records would be found at example.ca.

### Other DID methods

In the case of other DID methods, the association between a DID and a DNS domain is still possible although less obvious than with the aformentioned DID:WEB. The W3C DID Core spec supports multiple ways of creating the association between a DID to a domain. This is most intuitively accomplished one of two different fields.

**alsoKnownAs**: The assertion that two or more DIDs (or other types of URI, such as a domain name) refer to the same DID subject can be made using the {{alsoKnownAs}} property.

**Services**: Alternatively, {{services}} are used in DID documents to express ways of communicating with the DID subject or associated entities. In this case we are referring specifically to the "LinkedDomains" service type.

## DIDs with URI records

However, this association stemming only from the DID is unidirectional. By leveraging URI records as outlined in {{DID-in-the-DNS}}, we can create a bidirectional relationship, allowing a domain to publish their associated DIDs in the DNS.

***Ex: _did.example-issuer.ca IN URI 1 0 “did:example:XXXXXXX”***

This relationship enhances security, as an entity would require control over both the DID and the domain’s DNS server to create this bidirectional association, reducing the likelihood of malicious impersonation.

The ability for an organization to publish a list of their DIDs on the DNS is also beneficial as it establishes a link between the DNS, which is ubiquitously supported, and the distributed ledger (or other places) where the DID resides on which may not have the same degree of access or support, enhancing discoverability.

### URI record scoping

- The records MUST be scoped by setting the global underscore name of the URI RRset to *_did* (0x5F 0x64 0x69 0x64).

### Issuer Handles

An issuer may have multiple sub entities issuing credentials on their behalf, such as the different faculties in a university issuing diplomas. Each of these entities will need to be registered separately in a trust registry and will likely have one or more DIDs of their own. For this reason, the introduction of an issuer handle, represented as a subdomain in the resource record name, provides a simple way to facilitate the distinction of DIDs, their public keys, and credentials they issue in their relationship to the issuer.

***Ex: _did.diplomas.university-issuer.ca IN URI 1 0 “did:example:XXXXXXX”***

***Ex: _did.certificates.university-issuer.ca IN URI 1 0 “did:example:XXXXXXX”***

## PKI with TLSA records

The DID to DNS mapping illustrated in section 4 provides a way of showing the association between a DID and a domain, but no way of verifying that relationship. By hosting the public keys of that DID in its related domain’s zone, we can provide a cryptographic linkage to bolster this relationship while also providing access to the DID’s public keys outside of the distributed ledger where it resides, facilitating interoperability. If a verifier is presented with a credential issued or signed by a DID using a method they do not support, they would have the option to perform the cryptographic verification of the credential's signature using the public key stored in the DNS.

TLSA records {{!RFC6698}} provide a simple way of hosting cryptographic information in the DNS.

### TLSA Record Scoping, Selector Field

When public keys related to DIDs are published in the DNS as TLSA records:

- The records MUST be scoped by setting the global underscore name of the TLSA RRset to *_did* (0x5F 0x64 0x69 0x64).
- The Selector Field of the TLSA record must be set to 1, SubjectPublicKeyInfo: DER-encoded binary structure as defined in {{!RFC5280}}.

### Issuer Handles

As mentioned in section 4.2, an issuer may have multiple sub entities issuing credentials on their behalf, likely with their own set or sets of keypairs. Because these keypairs will need to be registered in a trust registry, and represented in the DNS as TLSA records, the use of an issuer Handle as outlined in section 4.2 will facilitate the distinction of the different public keys in their relation to the issuer.

***Ex: _did.diplomas.university-issuer.ca IN TLSA 3 1 0 “4e18ac22c00fb9...b96270a7b2”***

***Ex: _did.certificates.university-issuer.ca IN TLSA 3 1 0 “4e18ac22c00fb9...b96270a7b3”***

### Instances of Multiple DIDs

It is also likely an issuer may be using or wish to associate multiple DIDs with a single domain or subdomain. In this case it is possible to expand the name of the RRset using both the related DID method and identifier to more clearly associate the public key and its corresponding DID. In this circumstance, we propose using another 2 additional sub names, the first following the _did global identifier denoting the method, and the second denoting the DID's id.

***Ex: _did.example.1234abc.university-issuer.ca IN TLSA 3 1 0 “4e18ac22c00fb9...b96270a7b2”***

***Ex: _did.example.5678def.university-issuer.ca IN TLSA 3 1 0 “4e18ac22c00fb9...b96270a7b3”***

### Instances of Multiple Key Pairs

Depending on the needs of the issuer, it is possible they may use multiple keypairs associated with a single DID to sign and issue credentials. In this case a mechanism to differentiate which verificationMethod the public key is related to will need to be added to the name of the TLSA RRset.

A simple solution would be to create a standardized naming convention by expanding the RRset name using the fragment of the target verificationMethod's ID.

***Ex: _did.key-1.example-issuer.ca IN TLSA 3 1 0 "4e18ac22c00fb9...b96270a7b4"***

***Ex: _did.key-2.example-issuer.ca in TLSA 3 1 0 “4e18ac22c00fb9...b96270a7b5”***

### Benefits of Public Keys in the DNS

Hosting the public keys in TLSA records provides a stronger mechanism for the verifier to verify the issuer with, as they are able to perform a cryptographic challenge against the DID using the corresponding TLSA records, or against the domain using the corresponding {{verificationMethod}} in the DID document. The accessibility of the public keys is also beneficial, as the verifier does not need to resolve the DID document on a distributed ledger system they do not support to access the key material. This limits the burden of having to interoperate with a multitude of different distributed ledger technologies and transactions for credential verification, facilitating interoperability and adoption.

# Role of DNSSEC for Assurance and Revocation

It is a MUST that all the participants in this digital identity ecosystem enable DNSSEC signing for all the DNS instances they operate. See {{!RFC9364}}.

DNSSEC provides cryptographic assurance that the DNS records returned in response to a query are authentic and have not been tampered with. This assurance within the context of the *_did* URI and *_did* TLSA records provides another mechanism to ensure the integrity of the DID and its public keys outside of the distributed ledger it resides on directly from the domain of its owner.

Within this use-case, DNSSEC also provides revocation checks for both DIDs and public keys. In particular, a DNS query for a specific *_did* URI record or *_did* TLSA record can return an NXDOMAIN {{!RFC8020}} response if the DID or public key has been revoked. This approach can simplify the process of verifying the current validity of DIDs and public keys by reducing the need for complex revocation mechanisms or implementation specific technologies.

# Digital Signature and Proof Value of the DID Document

Digital signatures ensure the integrity of the DID Document, and by extent the public keys, authentication protocols, and service endpoints necessary for initiating trustworthy interactions with the identified entity. The use of digital signatures in this context provides a robust mechanism for verifying that the DID Document has not been tampered with and indeed originates from the correct entity.

In accordance with W3C specifications, we propose including a data integrity proof such as those outlined in these documents; https://www.w3.org/TR/vc-di-ecdsa/#proof-representations, https://www.w3.org/TR/vc-di-ecdsa/#proof-representations.

The data integrety proof MUST be signed using a verificationMethod that has an associated TLSA record to allow for the verification of the data integrity proof using data contained outside of the DID document. This provides an added layer of authenticity, as the information contained in the DID document would need to be supported accross 2 different domains.

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

## Inclusion of a TTL

To accompany the proof value, a TTL akin to the TTL of DNS resource records should also be included indicating to when a resolver should refresh and expect a new

# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.


1. Securing a DID with DNS
 - URI record
 - TLSA record
2. Securing DNS records with DNSSEC
3. Proof/Signature for the DID Document
4. Verification Procedure
5. 