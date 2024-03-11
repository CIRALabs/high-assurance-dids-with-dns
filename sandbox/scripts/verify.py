# Verify DNSSEC
# Verify URI and TLSA record match DID and verificationMethod
# Verify proof isn't expired
# Verify signature using verificationMethod

import json
from urllib.parse import urlparse
from dns import resolver, rdatatype
from joserfc.jwk import JWKRegistry
from cryptography.hazmat.primitives import serialization

import multibase
import requests
import argparse

resolver = resolver.Resolver()
resolver.use_dnssec = True
resolver.nameservers = ["8.8.8.8"]
resolver.timeout = 10


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


def download_did_document(did: str) -> dict:
    if did.split(":")[1] == "web":
        return resolve_did_web(did)
    else:
        return resolve_generic_did(did)


def resolve_did_web(did: str):
    did_web_url = _did_web_to_url(did)
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


def resolve_generic_did(did: str):
    resolver_url = f"https://uniresolver.io/1.0/identifiers/{did}"
    try:
        response = requests.get(resolver_url)
        response.raise_for_status()
        return response.json().get("didDocument")
    except requests.exceptions.RequestException as e:
        print(f"Error occurred: {e}")
        return None


def verify_proof(did_doc: dict):
    proof = did_doc.get("proof")
    if proof is None:
        raise ValueError("DID document does not contain a proof.")

    verification_methods = did_doc.get("verificationMethod")

    # get the verificationMethod
    target_verification_method_id = proof.get("verificationMethod")

    # If the verificationMethod belongs to another did, download that did doc and extract the verificationMethods
    if target_verification_method_id.split("#")[0] != did_doc.get("id"):
        new_did_doc = download_did_document(target_verification_method_id.split("#")[0])
        if new_did_doc is None:
            raise ValueError(
                "Signing verificationMethod belongs to a DID doc which does not exist."
            )
        verification_methods = new_did_doc.get("verificationMethod")

    # Sort through the verificationMethod set to get the correct one
    for verification_method in verification_methods:
        if verification_method.get("id") == target_verification_method_id:
            target_verification_method = verification_method

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


def extract_verification_method_to_der(verifcation_method):
    print(verifcation_method)
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


def dns_validate_did_document(did_doc: dict):
    if did_doc.get("id").startswith("did:web"):
        did_web_url = (
            did_doc.get("id").replace(":", "/").replace("did/web/", "https://")
        )
        domain = urlparse(did_web_url).netloc
    else:
        raise ValueError("Unsupported DID format for DNS validation.")
    response = resolver.resolve(f"_did.{domain}", rdatatype.URI)
    for uri_record in response:
        if uri_record.target.decode() != did_doc.get("id"):
            raise ValueError("URI record does not match DID.")

    response = resolver.resolve(f"_did.{domain}", rdatatype.TLSA)


def main(did: str):
    did_doc = download_did_document(did)
    dns_validate_did_document(did_doc)
    if did_doc is not None:
        try:
            verify_proof(did_doc)
            print("Proof verification successful.")
        except ValueError as e:
            print(f"Proof verification failed: {str(e)}")
    else:
        print("Failed to resolve DID document.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verify DID document proof")
    parser.add_argument("did", help="The DID to verify")
    parser.add_argument(
        "--use-dns",
        "-d",
        action="store_true",
        help="Use DNS records to validate the DID document",
    )
    args = parser.parse_args()

    main(args.did)
