from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os
import ecdsa
from ecdsa import SigningKey
import hashlib

import binascii
import base58
from binascii import unhexlify, hexlify
from verify_did import query_tlsa_record, verify_signature, verify_ecdsa_signature

# Path to your private key file (usually in PEM format)
private_key_file = 'keys/prime256v1/privkey.pem'

# Load the private key from the file
with open(private_key_file, 'rb') as key_file:
    private_key_pem = key_file.read()

# Load the private key from the PEM data
private_key = SigningKey.from_pem(private_key_pem)

public_key = private_key.get_verifying_key()
public_key_pem = public_key.to_pem()
public_key_bytes = hexlify(public_key.to_string()).decode()

print("public key",public_key_pem.decode())
print("public_key_bytes", public_key_bytes)

# Data to sign
data_to_sign = b"Data to be signed"

# Hashing the data before signing
hashed_data = hashlib.sha256(data_to_sign).digest()

# Sign the hashed data
signature = private_key.sign(data_to_sign,hashfunc=hashlib.sha256 )

signature_hex = hexlify(signature).decode()

print(signature_hex)

tlsa_record = query_tlsa_record("credentials.trustroot.ca",3,1,0)
verifying_public_key =tlsa_record.cert
public_key_2 = ecdsa.keys.VerifyingKey.from_der(verifying_public_key)

try:
    assert public_key_2.verify(signature, data_to_sign, hashfunc=hashlib.sha256)
    print("verified!!!")
except Exception as e:
        print(f"Error verifying signature: {e}")

#result = public_key_2.verify(signature, data_to_sign, hashfunc=hashlib.sha256)