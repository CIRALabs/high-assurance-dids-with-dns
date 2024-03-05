import hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from joserfc.jwk import ECKey
from ecdsa import SigningKey, VerifyingKey, NIST256p
import json
import base58
import hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64
import json
import sys


def generate_ed25519_verification_method_jwk() -> dict:
    """
    Generate a DID verification method for ed25519verificationkey2018 as a JWK.

    Returns:
        dict: A DID verification method for ed25519verificationkey2018 as a JWK.
    """
    print("Private key:")
    private_key = ECKey.generate_key(crv="P-256")
    print(json.dumps(private_key.as_dict(private=True), indent=4))
    verification_method = {
        "id": "did:web:example.com#key-1",
        "type": "Ed25519VerificationKey2018",
        "controller": "did:web:example.com",
        "publicKeyJwk": {private_key.as_dict(private=False)},
    }
    return verification_method


def generate_ed25519_verification_method_multibase() -> dict:
    """
    Generate a DID verification method for ed25519verificationkey2018 as multibase.

    Returns:
        dict: A DID verification method for ed25519verificationkey2018.
    """
    key = ed25519.Ed25519PrivateKey.generate()
    print(key.private_bytes())
    public_key = key.public_key()
    multibase_public_key = base58.b58encode(public_key.encode()).decode()
    id_ = f"did:web:example.com#key-{hashlib.sha256(public_key).hexdigest()}"
    verification_method = {
        "id": id_,
        "type": "Ed25519VerificationKey2018",
        "controller": "did:web:example.com",
        "publicKeyMultibase": multibase_public_key,
    }
    return verification_method


def generate_ecdsasecp256k1_verification_method_multibase() -> dict:
    """
    Generate a DID verification method for ecdsasecp256k1verificationkey2019.

    Returns:
        dict: A DID verification method for ecdsasecp256k1verificationkey2019.
    """
    private_key = SigningKey.generate(curve=NIST256p)
    print("Private Key:")
    print(private_key.to_pem())
    public_key = private_key.get_verifying_key()
    print("Public Key:")
    print(public_key.to_pem())
    multibase_public_key = base58.b58encode(public_key.to_string()).decode()
    id_ = "did:web:example.com#key-1"
    verification_method = {
        "id": id_,
        "type": "EcdsaSecp256k1VerificationKey2019",
        "controller": "did:web:example.com",
        "publicKeyMultibase": multibase_public_key,
    }
    print("VerificationMethod:")
    print(verification_method)


def generate_ecdsasecp256k1_verification_method_jwk() -> dict:
    """
    Generate a DID verification method for ecdsasecp256k1verificationkey2019 as JWK.

    Returns:
        dict: A DID verification method for ecdsasecp256k1verificationkey2019 as JWK.
    """
    private_key = ECKey.generate_key(crv="secp256k1")
    private_key_dict = private_key.as_dict(private=True)
    public_key_dict = private_key.as_dict(private=False)
    id_ = "did:web:example.com#key-1"
    verification_method = {
        "id": id_,
        "type": "EcdsaSecp256k1VerificationKey2019",
        "controller": "did:web:example.com",
        "publicKeyJwk": public_key_dict,
    }
    return verification_method


def generate_json_web_key_2020_verification_method() -> dict:
    """
    Generate a DID verification method for jsonwebkey2020.

    Returns:
        dict: A DID verification method for jsonwebkey2020.
    """
    private_key = ECKey.generate_key(crv="secp256k1")
    private_key_dict = private_key.as_dict(private=True)
    print("Private Key:")
    print(json.dumps(private_key_dict, indent=4))
    public_key_dict = private_key.as_dict(private=False)
    print("Public Key:")
    print(json.dumps(public_key_dict, indent=4))
    id_ = "did:web:example.com#key-1"
    print("Verification Method:")
    verification_method = {
        "id": id_,
        "type": "JsonWebKey2020",
        "controller": "did:web:example.com",
        "publicKeyJwk": public_key_dict,
    }
    print(json.dumps(verification_method, indent=4))


def convert_key_to_der():
    pass


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(
            "Usage: python generate_verification_methods.py <ed25519, ecdsasecp256k1, jsonwebkey2020> <jwk, multibase>"
        )
        sys.exit(1)

    verification_method_type = sys.argv[1]
    output_format = sys.argv[2]

    if verification_method_type == "ed25519" and output_format == "jwk":
        generate_ed25519_verification_method_jwk()
    elif verification_method_type == "ed25519" and output_format == "multibase":
        generate_ed25519_verification_method_multibase()
    elif verification_method_type == "ecdsasecp256k1" and output_format == "multibase":
        generate_ecdsasecp256k1_verification_method_multibase()
    elif verification_method_type == "ecdsasecp256k1" and output_format == "jwk":
        generate_ecdsasecp256k1_verification_method_jwk()
    elif verification_method_type == "jsonwebkey2020":
        generate_json_web_key_2020_verification_method()
    else:
        print("Invalid verification method type or output format.")
    # generate_ed25519_verification_method()
    # generate_ecdsasecp256k1_verification_method()
    generate_json_web_key_2020_verification_method()
