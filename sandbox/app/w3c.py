# Proofs for W3C Compliance
import json

import base58
import logging
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from joserfc.jwk import ECKey, OKPKey
import multibase

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from joserfc import jwk

SUPPORTED_CRYPTOSUITES = ["ecdsa-jcs-2019", "eddsa-jcs-2022"]


import argparse
import multibase
from datetime import datetime

EC_KEY_CURV = "secp256k1"

# https://www.w3.org/TR/did-spec-registries/#verification-method-types


def generate_ed25519_verification_method_jwk(did: str, verification_method_id: str, privkey_file: str):
    """
    Generate a DID verification method for ed25519verificationkey2018 as a JWK.

    Returns:
        dict: A DID verification method for ed25519verificationkey2018 as a JWK.
    """
    with open(privkey_file, "r", encoding="utf-8") as file:
        private_key_str = file.read()
    
    private_key_dict = json.loads(private_key_str)
    print("private_key_dict:", private_key_dict)
    private_key = OKPKey.import_key(private_key_dict)
    # private_key = OKPKey.generate_key("Ed25519")
    # print("Private key generated:", private_key)
    print(json.dumps(private_key.as_dict(private=True), indent=4))
    print("\nPublic key:")
    print(json.dumps(private_key.as_dict(private=False), indent=4))
    verification_method = {
        "id": did + "#" + verification_method_id,
        "type": "Ed25519VerificationKey2018",
        "controller": did,
        "publicKeyJwk": private_key.as_dict(private=False),
    }
    print("hello")
    print("\nVerificationMethod:")
    print(json.dumps(verification_method, indent=4))
    
    return verification_method, json.dumps(private_key.as_dict(private=True), indent=4)


def generate_ed25519_verification_method_multibase(
    did: str, verification_method_id: str
) -> dict:
    """
    Generate a DID verification method for ed25519verificationkey2018 as multibase.

    Returns:
        dict: A DID verification method for ed25519verificationkey2018.
    """
    key = ed25519.Ed25519PrivateKey.generate()
    print("Private key:")
    print(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
    )
    public_key = key.public_key()
    print("Public key:")
    print(
        public_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    )
    multibase_public_key = base58.b58encode(
        public_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).decode()
    verification_method = {
        "id": did + "#" + verification_method_id,
        "type": "Ed25519VerificationKey2018",
        "controller": did,
        "publicKeyMultibase": multibase_public_key,
    }
    print("VerificationMethod:")
    print(json.dumps(verification_method, indent=4))


def generate_ecdsasecp256k1_verification_method_multibase(
    did: str, verification_method_id: str
) -> dict:
    """
    Generate a DID verification method for ecdsasecp256k1verificationkey2019.

    Returns:
        dict: A DID verification method for ecdsasecp256k1verificationkey2019.
    """
    private_key = ECKey.generate_key(EC_KEY_CURV)
    print("Private Key:")
    print(private_key.as_pem().decode())
    print("Public Key:")
    print(private_key.as_pem(private=False).decode())
    multibase_public_key = multibase.encode(
        "base58btc", private_key.as_der(private=False)
    ).decode()
    verification_method = {
        "id": did + "#" + verification_method_id,
        "type": "EcdsaSecp256k1VerificationKey2019",
        "controller": did,
        "publicKeyMultibase": multibase_public_key,
    }
    print("VerificationMethod:")
    print(json.dumps(verification_method, indent=4))


def generate_ecdsasecp256k1_verification_method_jwk(
    did: str, verification_method_id: str
) -> dict:
    """
    Generate a DID verification method for ecdsasecp256k1verificationkey2019 as JWK.

    Returns:
        dict: A DID verification method for ecdsasecp256k1verificationkey2019 as JWK.
    """
    private_key = ECKey.generate_key(EC_KEY_CURV)
    private_key_dict = private_key.as_dict(private=True)
    print("Private Key:")
    print(json.dumps(private_key_dict, indent=4))
    public_key_dict = private_key.as_dict(private=False)
    print("\nPublic Key:")
    print(json.dumps(public_key_dict, indent=4))
    verification_method = {
        "id": did + "#" + verification_method_id,
        "type": "EcdsaSecp256k1VerificationKey2019",
        "controller": did,
        "publicKeyJwk": public_key_dict,
    }
    print("\nVerificationMethod:")
    print(json.dumps(verification_method, indent=4))

def extract_private_key(private_key: str) -> object | None:
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
            private_key = jwk.JWKRegistry.import_key(json.loads(private_key), None)
            return serialization.load_der_private_key(private_key.as_der(), None)
        except Exception as e:
            logging.error("Error occurred: %s", e)
            return None
    elif private_key.startswith("-----BEGIN"):  # PEM format
        try:
            private_key = private_key.strip().encode("utf-8")
            return serialization.load_pem_private_key(
                private_key, password=None, backend=default_backend()
            )
        except Exception as e:
            logging.error("Error occurred: %s", e)
            return None
    elif private_key.startswith("z"):  # Multibase format
        try:
            decoded_key = multibase.decode(private_key)
            return serialization.load_der_private_key(
                decoded_key, password=None, backend=default_backend()
            )
        except Exception as e:
            logging.error("Error occurred: %s", e)
            return None
    else:
        try:  # DER format
            return serialization.load_der_private_key(
                private_key, password=None, backend=default_backend()
            )
        except Exception as e:
            logging.error("Error occurred: %s", e)
            return None

def sign_did_doc(did_doc, target_verification_method, expiry, cryptosuite, private_key):
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
    # validate_verification_method(target_verification_method)

    # did_doc = download_did_document(did)

    print("sign_did_doc_private_key:", private_key)

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

    proof = {
            "type": "DataIntegrityProof",
            "cryptosuite": cryptosuite,
            "verificationMethod": f"{did_doc['id']}#{target_verification_method}",
            "created": datetime.now().isoformat(timespec="seconds"),
            "expires": expiry,
            "proofValue": encoded_signature,
        }

    return  proof
    

