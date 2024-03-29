import argparse
import hashlib
from urllib.parse import urlparse

import multibase
import requests
from joserfc.jwk import JWKRegistry
import logging


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
    logging.info("did_web_url: %s", did_web_url)
    return did_web_url


def resolve_did_web(did: str) -> dict | None:
    """
    Resolves a DID using the DID Web protocol.

    Args:
        did (str): The DID to resolve.

    Returns:
        dict or None: The resolved DID document as a dictionary, or None if the resolution failed.
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


def resolve_did_document(did: str) -> dict | None:
    """
    Resolve a DID (Decentralized Identifier) using the universal resolver API.

    Parameters:
    did (str): The DID to resolve.

    Returns:
    dict or None: The resolved DID document as a dictionary, or None if the resolution failed.
    """
    if did.startswith("did:web"):
        return resolve_did_web(did)
    response = requests.get(f"https://uniresolver.io/1.0/identifiers/{did}", timeout=5)
    if response.status_code == 200:
        return response.json().get("didDocument")
    else:
        return None


def convert_verification_method_to_tlsa_record(
    did: str, use_sha256: bool = False
) -> str | None:
    """
    Converts a verification method from a DID document to a TLSA record.

    Args:
        did (str): The DID (Decentralized Identifier) to resolve.

    Returns:
        str: The TLSA record generated from the verification method, or None if the conversion fails.

    Raises:
        Exception: If an error occurs during the conversion process.
    """
    did_document = resolve_did_document(did)
    if did_document is None:
        return None
    verification_methods = did_document.get("verificationMethod")
    if verification_methods is None:
        return None
    print("Select a verification method:")
    for i, method in enumerate(verification_methods):
        print(f"{i+1}. {method.get('id')}")
    selection = int(input("Enter the number of the verification method: ")) - 1
    if 0 <= selection < len(verification_methods):
        verification_method = verification_methods[selection]
        if verification_method.get("publicKeyMultibase"):
            try:
                public_key = verification_method.get("publicKeyMultibase")
                der_key = multibase.decode(public_key)
                if use_sha256:
                    return f"3 1 1 {hashlib.sha256(der_key).digest().hex()}"
                return f"3 1 0 {der_key.hex()}"
            except Exception as e:
                logging.error(e)
                return None
        elif verification_method.get("publicKeyJwk"):
            try:
                public_key = verification_method.get("publicKeyJwk")
                public_key = JWKRegistry.import_key(public_key).as_der()
                if use_sha256:
                    return f"3 1 1 {hashlib.sha256(public_key).digest().hex()}"
                return f"3 1 0 {public_key.hex()}"
            except Exception as e:
                logging.error(e)
                return None
        else:
            return None
    else:
        return None


def main(did: str, use_sha256: bool = False):
    tlsa_record = convert_verification_method_to_tlsa_record(did, use_sha256)
    if tlsa_record:
        return tlsa_record
    else:
        logging.error("Failed to generate TLSA record.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate TLSA record from verification method"
    )
    parser.add_argument("did", help="The DID to generate the TLSA record for")
    parser.add_argument(
        "-hash",
        "--sha256",
        help="Use SHA-256 hashing algorithm for the TLSA record",
        action="store_true",
    )
    args = parser.parse_args()

    print(main(args.did, args.sha256))
