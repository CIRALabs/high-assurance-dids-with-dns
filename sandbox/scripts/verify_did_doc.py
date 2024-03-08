import json
import sys
from binascii import unhexlify
from datetime import datetime
from urllib.parse import urlparse

import base58
import dns.message
import dns.rdata
import dns.rdatatype
import dns.resolver
import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_der_public_key,
)
from joserfc.jwk import JWKRegistry
from multibase import decode

import logging

logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s"
)


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

    print("did_web_url:", did_web_url)

    return did_web_url


def _extract_target_verifcation_method(
    did_doc: dict, target_verification_method_id: str
) -> dict:
    """
    Extracts the target verification method from the given DID document.

    Args:
        did_doc (dict): The DID document to extract the verification method from.
        target_verification_method_id (str): The ID of the target verification method.

    Returns:
        dict: The target verification method if found, otherwise False.
    """
    try:
        verificationMethods = did_doc.get("verificationMethod")
        for verificationMethod in verificationMethods:
            if target_verification_method_id == verificationMethod.get("id"):
                return verificationMethod
    except:
        return False
    return False


def query_tlsa_record(domain: str) -> dns.rdata:
    """
    Queries the TLSA records for a given domain.

    Args:
        domain (str): The domain to query the TLSA record for.
        matching_type (str): The matching type of the TLSA record.

    Returns:
        dns.rdata: The TLSA record matching the given domain and matching type,
                   or None if no matching record is found.
    """
    resolver = dns.resolver.Resolver()
    resolver.use_dnssec = True
    resolver.nameservers = ["8.8.8.8"]

    try:
        query_domain = "_did." + domain
        response = resolver.resolve(query_domain, "TLSA")

        tlsa_records = []
        for rdata in response:
            if rdata.usage == 3 and rdata.selector == 1 and rdata.mtype == 0:
                tlsa_records.append(rdata.cert)
        return tlsa_records

    except dns.resolver.NoAnswer:
        return None


def verify_signature(cryptosuite, signature, message, public_key):
    """
    Verify a signature using the specified cryptosuite.

    Args:
        cryptosuite (str): The cryptosuite used for the signature.
        signature (str): The signature to verify.
        message (str): The message that was signed.
        public_key (str): The public key used for verification.

    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    print(cryptosuite)
    print(signature)
    print(message)
    print(public_key)
    if cryptosuite == "ecdsa-jfc-2019":
        try:
            print("We're here")
            signature_bytes = base58.b58decode(signature)
            # print(public_key.sign)
            public_key.verify(signature_bytes, message, ec.ECDSA(hashes.SHA256()))
        except Exception as e:
            print(e)
            print("The signature is invalid.")
    elif cryptosuite == "eddsa-jcs-2022":
        try:
            signature_bytes = unhexlify(signature.encode())
            message_bytes = message.encode()
            public_key.verify(signature, message)
        except:
            print("The signature is invalid.")

    return False


def verify_did_doc(did_doc: dict):
    """
    Verify the integrity and authenticity of a DID document.

    Args:
        did_doc (dict): The DID document to be verified.
        did_web (str): The DID Web identifier.

    Returns:
        bool: True if the DID document is valid, False otherwise.
    """
    # Step 1: Verify did doc proof is not expired
    current_time = datetime.utcnow()
    exp_date = did_doc.get("proof").get("expires")
    if exp_date[-1] == "Z":
        exp_date = exp_date[:-1]
    exp_date = datetime.fromisoformat(exp_date)
    if exp_date >= current_time:
        print("OK: Not expired.")
    else:
        print(f"Invalid: Proof has expired - {did_doc.get('proof').get('expires')}")
        return False

    # Step 2: Determine the correct verificationMethod to verify the proof
    # i.e The verificationMethod used to generate the proof will either belong to the did doc being verified, or reference a verificationMethod belonging to another did
    proof_verification_method = did_doc.get("proof").get("verificationMethod")
    if proof_verification_method.split("#")[0] == did_doc.get("id"):
        target_verification_method = _extract_target_verifcation_method(
            did_doc, did_doc.get("proof").get("verificationMethod")
        )
    else:
        root_did_doc = download_did_document(proof_verification_method.split("#")[0])
        target_verification_method = _extract_target_verifcation_method(
            root_did_doc, did_doc.get("proof").get("verificationMethod")
        )

    # Step 3: Extract the verificationMethod public key to der format:
    der_format_verification_method = convert_verification_method_to_der(
        target_verification_method
    )

    print(target_verification_method)

    # Step 4: Extract domain from did:web identifier
    domain = urlparse(
        _did_web_to_url(target_verification_method.get("id").split("#")[0])
    ).hostname

    # Step 5: Verify the domain is also claimming ownership of the did doc via URI records

    # Step 6: Get public key from DNS/DNSSEC record
    tlsa_records = query_tlsa_record("_did." + domain)
    match = False
    for pub_key in tlsa_records:
        if pub_key == der_format_verification_method.public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        ):
            match = True
            break
    if not match:
        print(
            f"Invalid: verificationMethod {target_verification_method} doesn't match any corresponding TLSA records."
        )
        return False
    print("OK: Valid verificationMethod")
    proof = did_doc.pop("proof")
    # # Step 7: Verify the did doc proof

    verify_signature(
        proof.get("cryptosuite"),
        proof.get("proofValue"),
        json.dumps(did_doc).encode("utf-8"),
        der_format_verification_method,
    )


def download_did_document(did_web: str) -> dict:
    did_web_url = _did_web_to_url(did_web)
    try:
        response = requests.get(did_web_url)
        if response.status_code == 200:
            return response.json()
        else:
            print(
                f"Failed to download DID document. Status code: {response.status_code}"
            )
            return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def convert_verification_method_to_der(verificationMethod: dict) -> object:
    if verificationMethod.get("publicKeyJwk"):
        key = JWKRegistry.import_key(verificationMethod.get("publicKeyJwk"))
        return load_der_public_key(key.as_der())
    elif verificationMethod.get("publicKeyMultibase"):
        return load_der_public_key(decode(verificationMethod.get("publicKeyMultibase")))
    else:
        raise ValueError("Invalid verificationMethod format.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python verify_did_doc.py <did_web>")
        sys.exit(1)

    did_web = sys.argv[1]

    did_doc = download_did_document(did_web)

    print(json.dumps(did_doc, indent=4))

    # verify did doc using pubkey that was looked up on DNS
    result = verify_did_doc(did_doc)

    print("verify did doc", result)
