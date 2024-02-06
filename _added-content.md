# Content to incorportate

Among the various DID methods available, did:web serves as a practical starting point for those wanting to publish an easily discoverable decentralized identifier. The did:web method is easy to implement and compatible with existing web infrastructure. Did:web enables organizations to familiarize themselves with the core concepts of decentralized identities before implementing into more complex and specialized DID methods.

## Advantages of did:web

- Ease of Use: did:web is simpler to understand and implement and operates over standard HTTPS protocols. Did:web can be easily managed with familiar, widely available, robust and cheap web server technology.
- Simple discoverability: Resolving a DID to its DID document for did:web is straightforward. Discovering and resolving the did:web DID document relies on proven DNS technology and can be made more secure with DNSSEC extensions. The DID document can be requested by knowing only the did:web identifier of the DID.
- No Specialized Infrastructure: Did:web works with on existing DNS infrastructure and can be made more secure using DNSSEC.
- Low Cost: Did:web does not have an associated cost other than maintaining a web server and having a registered domain name.
- Interoperability: did:web identifiers can be easily mapped to existing HTTPS URLs, making it straightforward to integrate with current web architectures.

## Disadvantages of did:web

- No Trustworthiness: The main criticism of the did:web method for decentralized identities is its inability to ensure trust for the information it handles. The current web infrastructure is rife with vulnerabilities such as website hacking, DNS hijacking, and unreliable certificate authorities.
- DID document integrity: In the current did:web specification, signing of the DID document is not mandated. As a result, it becomes impossible to ascertain whether the content of the DID document is intact and unaltered or if it has been compromised.
- Trustworthiness of Trust Anchors: The did:web method relies on DNS and TLS as trust anchors. DNS resolves the domain name to an IP address and
TLS secures the transport mechanism, but together, DNS and TLS do not necessarily enhance the trustworthiness of the information being conveyed.
- Key Validity: If a private key becomes lost or compromised, it is essential to rotate the existing keys and associate a key public key with the DID. Currently, there is no formal approach in did:web to maintain validity of prior signatures, nullify signatures made with a compromised key or to enable new signatures using the updated key.

## Proposed Approach

The proposed approachi in this RFC is to enhance the did:web method, preserving its advantages, and addressing the key disadvantages. Together this would enable a did:web method of a given domain (e.g., did:web:issuer.example.gov) to be relied on as a high-assurance did:web.
