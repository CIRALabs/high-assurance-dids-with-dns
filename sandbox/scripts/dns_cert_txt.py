# Example of how to parse a TXT Record
from urllib.parse import parse_qs
from urllib.parse import urlparse


certificate_record = "cert:secp256k1/ecdsa?kid=02300d753f822691b63c0c79134aa2069c946768600a3fb32b6078b8209e75d203"
parsed_record = urlparse(certificate_record)
parsed_dict = parse_qs(parsed_record.query)

print(parsed_record.path)
print(parsed_dict)
pubkey = parsed_dict["kid"][0]
