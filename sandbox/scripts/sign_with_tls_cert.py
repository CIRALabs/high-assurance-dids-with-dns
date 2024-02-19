from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os
import ecdsa

import binascii
import base58
from binascii import unhexlify

from verify_did import query_tlsa_record, verify_signature, verify_ecdsa_signature

# run script from sandbox directory

# Path to your private key file (usually in PEM format)
private_key_file = 'keys/credentials/privkey.pem'

# The data you want to sign
data_to_sign = b"Data to be signed"

# Load the private key from the file
with open(private_key_file, "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,  # Provide a password if your key is encrypted
        backend=default_backend()
    )

public_key = private_key.public_key()
pem_public_key = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

print(pem_public_key.decode())
# Sign the data
  
der_public_key = public_key.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

hex_public_key = binascii.hexlify(der_public_key).decode()

print(hex_public_key)

# The signature is now stored in 'signature' variable
# You can, for example, write it to a file or send it over a network

signature = private_key.sign(
    data_to_sign,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
print(signature)
signature_str = base58.b58encode(signature).decode()
print(signature_str)
signature_bytes = base58.b58decode(signature_str.encode())
print(signature_bytes)

public_key_der = serialization.load_der_public_key(binascii.unhexlify(hex_public_key))

# public_key_to_verify = ecdsa.keys.VerifyingKey.from_der(public_key_der)
tlsa_record = query_tlsa_record("credentials.trustroot.ca", 3, 1, 0)
public_key_dns = tlsa_record.cert



# verify_ecdsa_signature(signature_bytes,data_to_sign,der_public_key)

print("############ECDSA#################")
private_key_file = 'keys/test/privkey.pem'

with open(private_key_file, 'rb') as key_file:
    private_key_pem = key_file.read()



private_key =ecdsa.SigningKey.from_pem(private_key_pem)
