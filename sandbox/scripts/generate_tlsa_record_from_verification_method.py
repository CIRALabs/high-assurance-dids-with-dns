import argparse

import multibase
import requests
from joserfc.jwk import JWKRegistry


import requests


def resolve_did_document(did):
    """
    Resolve a DID (Decentralized Identifier) using the universal resolver API.

    Parameters:
    did (str): The DID to resolve.

    Returns:
    dict or None: The resolved DID document as a dictionary, or None if the resolution failed.
    """
    # Send a GET request to the universal resolver API
    response = requests.get(f"https://uniresolver.io/1.0/identifiers/{did}")
    if response.status_code == 200:
        return response.json().get("didDocument")
    else:
        return None


def convert_verification_method_to_tlsa_record(did):
    """
    Converts a verification method from a DID document to a TLSA record.

    Args:
        did (str): The DID (Decentralized Identifier) to resolve.

    Returns:
        str: The TLSA record generated from the verification method, or None if the conversion fails.

    Raises:
        Exception: If an error occurs during the conversion process.
    """
    # Resolve the DID document
    did_document = resolve_did_document(did)
    if did_document is None:
        return None
    # Get the verification methods from the DID document
    verification_methods = did_document.get("verificationMethod")
    if verification_methods is None:
        return None
    # Ask the user to select a verification method
    print("Select a verification method:")
    for i, method in enumerate(verification_methods):
        print(f"{i+1}. {method.get('id')}")
    selection = int(input("Enter the number of the verification method: ")) - 1
    if 0 <= selection < len(verification_methods):
        verification_method = verification_methods[selection]
        # Check if verificationMethod type is publicKeyMultibase
        if verification_method.get("publicKeyMultibase"):
            try:
                public_key = verification_method.get("publicKeyMultibase")
                der_key = multibase.decode(public_key)
                tlsa_record = f"3 1 0 {der_key.hex()}"
                return tlsa_record
            except Exception as e:
                print(e)
                return None
        # Check if verificationMethod type is publicKeyJwk
        elif verification_method.get("publicKeyJwk"):
            try:
                public_key = verification_method.get("publicKeyJwk")
                public_key = JWKRegistry.import_key(public_key)
                tlsa_record = f"3 1 0 {public_key.as_der().hex()}"
                return tlsa_record
            except Exception as e:
                print(e)
                return None
        # Return None if verificationMethod type is not supported
        else:
            return None
    else:
        return None


def main(did):
    tlsa_record = convert_verification_method_to_tlsa_record(did)
    if tlsa_record:
        return tlsa_record
    else:
        print("Failed to generate TLSA record.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate TLSA record from verification method"
    )
    parser.add_argument("DID", help="The DID to generate the TLSA record for")
    args = parser.parse_args()

    main(args.DID)
