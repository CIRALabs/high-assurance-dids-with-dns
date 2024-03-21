import json

import base58
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from joserfc.jwk import ECKey, OKPKey
import argparse
import multibase

EC_KEY_CURV = "secp256k1"

# https://www.w3.org/TR/did-spec-registries/#verification-method-types


def generate_ed25519_verification_method_jwk(
    did: str, verification_method_id: str
) -> dict:
    """
    Generate a DID verification method for ed25519verificationkey2018 as a JWK.

    Returns:
        dict: A DID verification method for ed25519verificationkey2018 as a JWK.
    """
    print("Private key:")
    private_key = OKPKey.generate_key("Ed25519")
    print(json.dumps(private_key.as_dict(private=True), indent=4))
    print("\nPublic key:")
    print(json.dumps(private_key.as_dict(private=False), indent=4))
    verification_method = {
        "id": did + "#" + verification_method_id,
        "type": "Ed25519VerificationKey2018",
        "controller": did,
        "publicKeyJwk": private_key.as_dict(private=False),
    }
    print("\nVerificationMethod:")
    print(json.dumps(verification_method, indent=4))


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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate DID verification methods.")
    parser.add_argument(
        "verification_method_type",
        choices=["ed25519", "ecdsasecp256k1"],
        help="The verificationMethod type",
    )
    parser.add_argument(
        "output_format", choices=["jwk", "multibase"], help="The output format"
    )
    parser.add_argument("did", help="The DID to generate the verification method for")
    parser.add_argument(
        "verification_method_id",
        help="The id of the verification method to generate",
    )
    args = parser.parse_args()

    if args.verification_method_type == "ed25519" and args.output_format == "jwk":
        generate_ed25519_verification_method_jwk(args.did, args.verification_method_id)
    elif (
        args.verification_method_type == "ed25519" and args.output_format == "multibase"
    ):
        generate_ed25519_verification_method_multibase(
            args.did, args.verification_method_id
        )
    elif (
        args.verification_method_type == "ecdsasecp256k1"
        and args.output_format == "multibase"
    ):
        generate_ecdsasecp256k1_verification_method_multibase(
            args.did, args.verification_method_id
        )
    elif (
        args.verification_method_type == "ecdsasecp256k1"
        and args.output_format == "jwk"
    ):
        generate_ecdsasecp256k1_verification_method_jwk(
            args.did, args.verification_method_id
        )
    else:
        print("Invalid verification method type or output format.")
