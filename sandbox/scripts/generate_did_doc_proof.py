import argparse
import json
from datetime import datetime

import multibase
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from joserfc import jwk


def download_did_document(did):
    """
    Downloads the DID document for the given DID from the UniResolver API.

    Args:
        did (str): The decentralized identifier (DID) to download the document for.

    Returns:
        dict or None: The downloaded DID document as a dictionary, or None if an error occurred.

    Raises:
        requests.exceptions.RequestException: If an error occurs while making the HTTP request.
    """
    resolver_url = f"https://uniresolver.io/1.0/identifiers/{did}"
    try:
        response = requests.get(resolver_url)
        response.raise_for_status()
        return response.json().get("didDocument")
    except requests.exceptions.RequestException as e:
        print(f"Error occurred: {e}")
        return None


def extract_private_key(private_key):
    """
    Extracts a private key from various formats and returns a loaded private key object.

    Args:
        private_key (str): The private key in one of the supported formats.

    Returns:
        object: The loaded private key object.

    Raises:
        Exception: If an error occurs during the extraction process.

    """
    if private_key.startswith("{"):  # JWK format
        try:
            private_key = jwk.JWKRegistry.import_key(json.loads(private_key))
            return serialization.load_der_private_key(private_key.as_der(), None)
        except Exception as e:
            print(f"Error occurred: {e}")
            return None
    elif private_key.startswith("-----BEGIN"):  # PEM format
        try:
            private_key = private_key.strip().encode("utf-8")
            return serialization.load_pem_private_key(
                private_key, password=None, backend=default_backend()
            )
        except Exception as e:
            print(f"Error occurred: {e}")
            return None
    elif private_key.startswith("z"):  # Multibase format
        try:
            decoded_key = multibase.decode(private_key)
            return serialization.load_der_private_key(
                decoded_key, password=None, backend=default_backend()
            )
        except Exception as e:
            print(f"Error occurred: {e}")
            return None
    else:
        try:  # DER format
            return serialization.load_der_private_key(
                private_key, password=None, backend=default_backend()
            )
        except Exception as e:
            print(f"Error occurred: {e}")
            return None


def validate_verification_method(target_verification_method):
    """
    Validates the given target verification method.

    Args:
        target_verification_method (str): The target verification method to validate.

    Raises:
        ValueError: If no verification methods are found in the DID document or if the verification method is invalid.
    """
    verification_method_did = target_verification_method.split("#")[0]
    verification_method_did_doc = download_did_document(verification_method_did)
    if verification_method_did_doc.get("verificationMethod") is None:
        raise ValueError("No verification methods found in the DID document")
    valid_verification_method = False
    for verification_method in verification_method_did_doc.get("verificationMethod"):
        if verification_method.get("id") == target_verification_method:
            valid_verification_method = True
            break
    if valid_verification_method is False:
        raise ValueError("Invalid verification method")


def sign_did(did, target_verification_method, expiry, cryptosuite, private_key):
    """
    Signs a DID document with the provided parameters.

    Args:
        did (str): The DID (Decentralized Identifier) to sign.
        target_verification_method (str): The verification method to use for signing.
        expiry (str): The expiration date of the signature.
        cryptosuite (str): The cryptographic suite to use for signing.
        private_key (object): The private key used for signing.

    Returns:
        dict: A dictionary representing the signed DID document.

    Raises:
        ValueError: If the cryptosuite or private key type is invalid.
    """

    validate_verification_method(target_verification_method)

    did_doc = download_did_document(did)
    if did_doc.get("proof") is not None:
        del did_doc["proof"]

    # Canonicalize the DID doc
    canonical_json = json.dumps(did_doc, sort_keys=True)

    private_key = extract_private_key(private_key)

    if cryptosuite == "ecdsa-jcs-2019" and isinstance(
        private_key, ec.EllipticCurvePrivateKey
    ):
        signature = private_key.sign(
            canonical_json.encode("utf-8"),
            ec.ECDSA(hashes.SHA256()),
        )
    elif cryptosuite == "eddsa-jcs-2022" and isinstance(private_key, Ed25519PrivateKey):
        signature = private_key.sign(
            canonical_json.encode("utf-8"),
        )
    else:
        raise ValueError("Invalid cryptosuite or private key type")

    # Base58 encode the signature
    encoded_signature = multibase.encode("base58btc", signature).decode("utf-8")

    return {
        "proof": {
            "type": "DataIntegrityProof",
            "cryptosuite": cryptosuite,
            "verificationMethod": target_verification_method,
            "created": datetime.now().isoformat(timespec="seconds"),
            "expires": expiry,
            "proofValue": encoded_signature,
        }
    }


def main(did, verification_method, expiry, cryptosuite, path):
    with open(path, "r", encoding="utf-8") as file:
        private_key = file.read()
    signature = sign_did(did, verification_method, expiry, cryptosuite, private_key)
    return signature


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a DID Document proof")
    parser.add_argument(
        "cryptosuite", help="Cryptosuite, either 'ecdsa-jcs-2019' or 'eddsa-jcs-2022'."
    )
    parser.add_argument("did", help="The DID to generate the proof for.")
    parser.add_argument(
        "verificationMethod", help="verificationMethod the signature belongs to."
    )
    parser.add_argument(
        "expiry", help="ISO format date time for the expiry of the proof."
    )
    parser.add_argument(
        "path",
        help="Path to a file containing the private key to generate the proof with.",
    )
    args = parser.parse_args()
    print(
        json.dumps(
            main(
                args.did,
                args.verification_method,
                args.expiry,
                args.cryptosuite,
                args.private_key,
            ),
            indent=4,
        )
    )
