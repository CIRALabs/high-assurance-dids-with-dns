import argparse
import hashlib
import json
import logging
from typing import Optional
from urllib.parse import urlparse

import dns
from dns import dnssec
import multibase
import requests
from cryptography.hazmat.primitives import serialization
from dns import rdatatype, resolver
from joserfc.jwk import JWKRegistry
import ssl, socket
from OpenSSL import crypto

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from binascii import unhexlify, hexlify

resolver = resolver.Resolver()
resolver.use_dnssec = True
resolver.nameservers = ["8.8.8.8"]
resolver.timeout = 10

logging.basicConfig(level=logging.INFO)


def _did_web_to_url(did_web: str) -> str:
    """
    Converts a DID Web identifier to a URL pointing to the corresponding DID document.

    Args:
        did_web (str): The DID Web identifier to convert.

    Returns:
        str: The URL pointing to the corresponding DID document.
    """
    did_web_url = did_web.replace(":", "/").replace("did/web/", "https://")
    parsed_url = urlparse(did_web_url)
    if parsed_url.path == "":
        did_web_url = did_web_url + "/.well-known/did.json"
    else:
        did_web_url = did_web_url + "/did.json"
    
    if parsed_url.fragment != "":
        did_web_url = did_web_url.replace("#"+parsed_url.fragment, "" )
    
    return did_web_url


def _resolve_did_web(did: str) -> Optional[dict]:
    """
    Resolves a DID using the DID Web method.

    Args:
        did (str): The DID to resolve.

    Returns:
        dict or None: The resolved DID document as a dictionary, or None if resolution fails.
    """
    did_web_url = _did_web_to_url(did)
    try:
        response = requests.get(did_web_url, timeout=5)
        if response.status_code == 200:
            return response.json()
        logging.error(
            "Failed to download DID document. Status code: %s", response.status_code
        )
        return None
    except Exception as e:
        logging.error("An error occurred: %s", e)
        return None


def _resolve_generic_did(did: str) -> Optional[dict]:
    """
    Resolves a generic DID using the UniResolver API.

    Args:
        did (str): The generic DID to resolve.

    Returns:
        dict or None: The resolved DID document as a dictionary, or None if an error occurred.

    """
    resolver_url = f"https://uniresolver.io/1.0/identifiers/{did}"
    try:
        response = requests.get(resolver_url)
        response.raise_for_status()
        return response.json().get("didDocument")
    except requests.exceptions.RequestException as e:
        logging.error("Error occurred: %s", e)
        return None


def download_did_document(did: str) -> dict:
    """
    Downloads the DID document for the given DID.

    Args:
        did (str): The DID (Decentralized Identifier) to download the document for.

    Returns:
        dict: The downloaded DID document.

    Raises:
        ValueError: If the DID is not in the expected format.

    """
    if did.split(":")[1] == "web":
        return _resolve_did_web(did)
    return _resolve_generic_did(did)


def verify_proof(did_doc: dict) -> dict:
    """
    Verifies the proof of a DID document.

    Args:
        did_doc (dict): The DID document to verify.

    Returns:
        dict: The verification method used for the proof.

    Raises:
        ValueError: If the DID document does not contain a proof.
        ValueError: If the signing verificationMethod belongs to a DID doc which does not exist.
        ValueError: If the signing verificationMethod does not exist in the DID document.
    """
    proof = did_doc.get("proof")
    if proof is None:
        raise ValueError("DID document does not contain a proof.")
    logging.info("DID document proof: %s", json.dumps(proof, indent=2))
    verification_methods = did_doc.get("verificationMethod")
    target_verification_method_id = proof.get("verificationMethod")
    print("***", proof, target_verification_method_id)
    if target_verification_method_id.split("#")[0] != did_doc.get("id"):
        new_did_doc = download_did_document(target_verification_method_id.split("#")[0])
        if new_did_doc is None:
            raise ValueError(
                "Signing verificationMethod belongs to a DID doc which does not exist."
            )
        verification_methods = new_did_doc.get("verificationMethod")
    for verification_method in verification_methods:
        if verification_method.get("id") == target_verification_method_id:
            target_verification_method = verification_method
    logging.info(
        "Signing verificationMethod: %s",
        json.dumps(target_verification_method, indent=2),
    )
    if target_verification_method is None:
        raise ValueError(
            "Signing verificationMethod does not exist in the DID document."
        )
    public_key = extract_verification_method_to_der(target_verification_method)
    del did_doc["proof"]
    canonical_did_doc = json.dumps(did_doc, sort_keys=True)
    public_key.verify(
        multibase.decode(proof.get("proofValue")), canonical_did_doc.encode("utf-8")
    )
    logging.info("Succesfully verified proof using: %s", target_verification_method_id)
    return target_verification_method


def extract_verification_method_to_der(
    verifcation_method: dict,
) -> serialization.load_der_public_key:
    """
    Extracts the verification method to DER format.

    Args:
        verifcation_method (dict): The verification method.

    Returns:
        cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey: The extracted public key in DER format.

    Raises:
        ValueError: If the verificationMethod format is unsupported.
    """
    if verifcation_method.get("publicKeyJwk"):
        public_key = verifcation_method.get("publicKeyJwk")
        public_key = JWKRegistry.import_key(public_key)
        return serialization.load_der_public_key(public_key.as_der(), None)
    elif verifcation_method.get("publicKeyMultibase"):
        public_key = verifcation_method.get("publicKeyMultibase")
        return serialization.load_der_public_key(
            multibase.decode(public_key).encode(), None
        )
    else:
        raise ValueError("Unsupported verificationMethod format.")


def validate_uri_record(did_doc: dict, domain: str, do_dnssec: bool = False) -> None:
    """
    Validates the URI record for a given DID document and domain.

    Args:
        did_doc (dict): The DID document to validate against.
        domain (str): The domain to resolve the URI record for.
        do_dnssec (bool, optional): Flag indicating whether to use DNSSEC for resolution. Defaults to False.

    Raises:
        ValueError: If the URI record does not match the DID.

    Returns:
        None
    """
    logging.info("Validating URI record matches %s...", did_doc.get("id"))
    if do_dnssec:
        response = resolve_dns_record_with_dnssec(f"_did.{domain}", rdatatype.URI)
    else:
        response = resolver.resolve(f"_did.{domain}", rdatatype.URI)
    logging.info("Resolved URI records: %s", response)
    uri_record_match = False
    for uri_record in response:
        if uri_record.target.decode() == did_doc.get("id"):
            logging.info("URI record matches %s.", did_doc.get("id"))
            uri_record_match = True
    if uri_record_match is False:
        raise ValueError("URI record does not match DID.")


def validate_tlsa_record(
    verificationMethod: dict, domain: str, do_dnssec: bool = False
) -> None:
    """
    Validates the TLSA record for a given verification method and domain.

    Args:
        verificationMethod (str): The verification method to be validated.
        domain (str): The domain for which the TLSA record is being validated.
        do_dnssec (bool, optional): Flag indicating whether DNSSEC should be used for DNS resolution. Defaults to False.

    Raises:
        ValueError: If no TLSA record corresponding to the verificationMethod is found.

    Returns:
        None
    """
    logging.info("Validating TLSA record matches %s...", verificationMethod.get("id"))
    if do_dnssec:
        response = resolve_dns_record_with_dnssec(f"_did.{domain}", rdatatype.TLSA)
    else:
        response = resolver.resolve(f"_did.{domain}", rdatatype.TLSA)
    key = extract_verification_method_to_der(verificationMethod).public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    valid_tlsa_record = False
    logging.info("Resolved TLSA records: %s", response)
    for tlsa_record in response:
        if (
            tlsa_record.usage == 3
            and tlsa_record.selector == 1
            and tlsa_record.mtype == 0
        ):
            if tlsa_record.cert.hex() == key.hex():
                logging.info("TLSA record matches %s.", verificationMethod.get("id"))
                valid_tlsa_record = True
                break
        elif (
            tlsa_record.usage == 3
            and tlsa_record.selector == 1
            and tlsa_record.mtype == 0
        ):
            if tlsa_record.cert.hex() == hashlib.sha256(key).hexdigest():
                logging.info("TLSA record matches %s.", verificationMethod.get("id"))
                valid_tlsa_record = True
                break
    if not valid_tlsa_record:
        raise ValueError(
            f"No TLSA record corresponding to {verificationMethod.get('id')} found."
        )


def validate_dnskey_with_ds(zone: str) -> bool:
    """
    Validates the DNSKEY records of a domain against the DS records of its parent domain.

    Args:
        domain (str): The domain to validate.

    Returns:
        bool: True if the DNSKEY records are valid, False otherwise.
    """
    try:
        dnskey_answer = resolver.resolve(zone, dns.rdatatype.DNSKEY)
        ds_answer = resolver.resolve(zone, dns.rdatatype.DS)
        dnskey_rrset = dnskey_answer.rrset
        ds_rrset = ds_answer.rrset
        for dnskey in dnskey_rrset:
            valid = False
            for ds in ds_rrset:
                if dns.dnssec.make_ds(zone, dnskey, ds.digest_type) == ds:
                    valid = True
            if valid is False:
                return False
        return True
    except Exception as e:
        logging.error(e)
        return False


def resolve_dns_record_with_dnssec(
    record_name: str, record_type: str
) -> dns.rrset.RRset:
    """
    Resolves a DNS record using DNSSEC validation up to its parent domain.

    Args:
        record_name (str): The name of the DNS record to resolve.
        record_type (int): The type of the DNS record to resolve.

    Raises:
        ValueError: If DNSKEY validation fails for the zone.
        dns.resolver.NXDOMAIN: If the DNS domain does not exist.
        dns.resolver.NoAnswer: If no records are found for the given record name and type.
        dns.resolver.NoNameservers: If no nameservers are found.
        Exception: If any other error occurs.

    Returns:
        dns.rrset.RRset: The resolved DNS record as an RRset object.
    """
    try:
        logging.info(
            "Performing DNSSEC validation for %s record %s...", record_type, record_name
        )
        zone = dns.name.from_text(record_name).parent()
        try:
            soa_record = resolver.resolve(zone, rdatatype.SOA)
            zone = dns.name.from_text(soa_record.mname.split(".")[1:])
        except Exception as e:
            zone = dns.name.from_text(".".join(zone.to_text(True).split(".")[-2:]))
        if not validate_dnskey_with_ds(zone):
            raise ValueError(f"DNSKEY validation failed for {zone}")
        dnskey_answer = resolver.resolve(zone, dns.rdatatype.DNSKEY)
        query = dns.message.make_query(record_name, record_type, want_dnssec=True)
        (response, _) = dns.query.udp_with_fallback(query, "8.8.8.8")
        rrset, rrsig = response.answer
        dns.dnssec.validate(
            rrset,
            rrsig,
            {zone: dnskey_answer},
        )
        logging.info(
            "DNSSEC validation succesfull for %s record %s.", record_type, record_name
        )
        return rrset
    except dns.resolver.NXDOMAIN:
        logging.error("DNS domain '%s' does not exist.", record_name)
    except dns.resolver.NoAnswer:
        logging.error("No records found for '%s %s'.", record_name, record_type)
    except dns.resolver.NoNameservers:
        logging.error("No nameservers found.")
    except Exception as e:
        logging.error("Error occurred: %s", e)


def dns_validate_did_document(
    did_doc: dict,
    verificationMethod: dict,
    use_dnssec: bool = False,
) -> None:
    """
    Validates the DID document using DNS records.

    Args:
        did_doc (dict): The DID document to be validated.
        verificationMethod (dict): The verification method to be validated.
        use_dnssec (bool, optional): Flag indicating whether to use DNSSEC for validation. Defaults to False.

    Raises:
        ValueError: If the DID format is unsupported for DNS validation.
    """
    if did_doc.get("id").startswith("did:web"):
        did_web_url = (
            did_doc.get("id").replace(":", "/").replace("did/web/", "https://")
        )
        domain = urlparse(did_web_url)
        if domain.path:
            domain = domain.path.strip("/") + "." + domain.netloc
        else:
            domain = domain.hostname
    else:
        raise ValueError("Unsupported DID format for DNS validation.")
    validate_uri_record(did_doc, domain, use_dnssec)
    validate_tlsa_record(verificationMethod, domain, use_dnssec)

def dns_txt_validate_did_document(
    did_doc: dict,
    verificationMethod: dict    
) -> None:
    """
    Validates the DID document using DNS records.

    Args:
        did_doc (dict): The DID document to be validated.
        verificationMethod (dict): The verification method to be validated.
        use_dnssec (bool, optional): Flag indicating whether to use DNSSEC for validation. Defaults to False.

    Raises:
        ValueError: If the DID format is unsupported for DNS validation.
    """
    if did_doc.get("id").startswith("did:web"):
        did_web_url = (
            did_doc.get("id").replace(":", "/").replace("did/web/", "https://")
        )
        domain = urlparse(did_web_url)
        if domain.path:
            domain = domain.path.strip("/") + "." + domain.netloc
        else:
            domain = domain.hostname
    else:
        raise ValueError("Unsupported DID format for DNS validation.")
    # validate_uri_record(did_doc, domain, use_dnssec)
    # validate_tlsa_record(verificationMethod, domain, use_dnssec)

def query_did_dns_txt_record(domain_record):
    resolver = dns.resolver.Resolver()
    resolver.use_dnssec = True
    resolver.nameservers = ['8.8.8.8']
    resolver.use_edns = True

    try:
        query_domain = domain_record        
        response = resolver.resolve(query_domain, 'TXT')
        answer_txt= str(response[0]).strip("\"")
        logging.debug(f"OK: query_domain {query_domain} answer_txt {answer_txt}")
        return answer_txt

    except dns.resolver.NoAnswer:
        return None, None

def get_tls_public_key(host, port=443):
    # Create a socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Create an SSL context without certificate verification
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    # Wrap the socket with SSL
    wrapped_socket = context.wrap_socket(sock, server_hostname=host)

    # Connect and retrieve the certificate
    wrapped_socket.connect((host, port))
    der_cert = wrapped_socket.getpeercert(True)
    wrapped_socket.close()

    # Convert to X509
    x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, der_cert)

    # Extract the public key
    public_key = x509.get_pubkey()
    public_key_pem = crypto.dump_publickey(crypto.FILETYPE_PEM, public_key)
    # print(public_key_pem)

    public_key_obj = serialization.load_pem_public_key(
        public_key_pem,
        backend=default_backend()
    )

    public_key_bytes = public_key_obj.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return hexlify(public_key_bytes).decode().upper()
def main(did: str, use_dns: bool = False, use_dnssec: bool = False, use_dnstxt: bool = False) -> None:
    did_doc = download_did_document(did)
    if did_doc is not None:
        try:
            logging.info(
                "Resolved DID document for %s: %s", did, json.dumps(did_doc, indent=2)
            )
            logging.info("Verifying DID document proof...")
            target_verification_method = verify_proof(did_doc)
        except ValueError as e:
            raise ValueError(f"Proof verification failed: {str(e)}") from e
    else:
        raise ValueError("Failed to download DID document.")

    if use_dns:
        try:
            logging.info("Validating DID document using DNS records...")
            dns_validate_did_document(did_doc, target_verification_method, use_dnssec)
            logging.info("DNS validation successful.")
        except ValueError as e:
            logging.error(f"DNS validation failed: {str(e)}")
    if use_dnstxt:
        logging.info(f"Validating DID document using DNS TXT records...")
        answer_did = query_did_dns_txt_record("_did.openproof.org")
        print("answer did:", answer_did)
        answer_tlsa = query_did_dns__txt_record("_tlsa.openproof.org")
        print("answer tlsa:", answer_tlsa)
        answer_did_doc = dns_txt_validate_did_document(did_doc, target_verification_method)
        print("answer:", answer_did_doc)
        answer_wspubkey = get_tls_public_key("trustroot.ca")
        print("answer:", answer_wspubkey)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verify DID document proof")
    parser.add_argument("did", help="The DID to verify")
    parser.add_argument(
        "--use-dns",
        "-dns",
        action="store_true",
        help="Use DNS records to validate the DID document",
    )
    parser.add_argument(
        "--use-dnssec",
        "-dnssec",
        action="store_true",
        help="Use DNSSEC to validate the DNS records for the DID document",
    )
    parser.add_argument(
        "--use-dnstxt",
        "-dnstxt",
        action="store_true",
        help="Use DNS TXT records to validate the DNS records for the DID document",
    )
    args = parser.parse_args()

    main(args.did, args.use_dns, args.use_dnssec, args.use_dnstxt)
