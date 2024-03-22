import argparse
import hashlib
import json
import logging
from typing import Optional
from urllib.parse import urlparse

import dns
from dns import dnssec
import multibase
import requests
from cryptography.hazmat.primitives import serialization
from dns import rdatatype, resolver
from joserfc.jwk import JWKRegistry
import ssl, socket
from OpenSSL import crypto

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from binascii import unhexlify, hexlify

resolver = resolver.Resolver()
resolver.use_dnssec = True
resolver.nameservers = ["8.8.8.8"]
resolver.timeout = 10

logging.basicConfig(level=logging.INFO)


def did_web_to_url(did_web):
    # Routine to transform did_web into corresponding url
    did_web = "did:web:" + did_web if did_web[:7] != 'did:web' else did_web

    # replace colon with slash and encoded colon with colon

    did_web_url = did_web.replace(":", "/").replace('did/web/', "https://").replace('%3A',':')
    
    parsed_url = urlparse(did_web_url)
   

    authority = parsed_url.netloc
    if "@" in authority:
        authority_parts = authority.split('@')
        did_web_url = parsed_url.scheme + "://" + authority_parts[1] + "/" + authority_parts[0] + "/did.json"
    else:   
        if parsed_url.path == '':
            did_web_url = did_web_url + '/.well-known/did.json'
        else:
            did_web_url = did_web_url + "/did.json"   
    
        # strip out fragment and params    
        did_web_url = did_web_url.replace('#'+ parsed_url.fragment,'').replace(parsed_url.query,'').replace('?','')    
    
    # add in fragment as a directive
    if parsed_url.fragment:
        did_web_url = did_web_url + f"/?directive={parsed_url.fragment}"
        print("with directive:", did_web_url )
        
    
    return did_web_url


def _resolve_did_web(did: str) -> Optional[dict]:
    """
    Resolves a DID using the DID Web method.

    Args:
        did (str): The DID to resolve.

    Returns:
        dict or None: The resolved DID document as a dictionary, or None if resolution fails.
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
    
def main(did: str):

    did_url = did_web_to_url(did)

    parsed_url = urlparse(did_url)

    domain = parsed_url.hostname
    try:
        response = resolver.resolve(f"_did.{domain}", rdatatype.URI)
        uri_record_match = False
        for uri_record in response:
            print(uri_record.target.decode()) 
    except:
        logging.error("Record does not exist")

    try:
        response = resolver.resolve(f"_did.{domain}", rdatatype.TLSA)
        # print(response.response)
        for tlsa_record in response:
            if tlsa_record.usage == 3 and tlsa_record.selector == 1 and tlsa_record.mtype == 0:
                print(tlsa_record.cert.hex())
        
    except:
        logging.error("Record does not exist")
    
    print("done")   

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verify DID document proof")
    parser.add_argument("did", help="The DID to resolve")
   
    args = parser.parse_args()

   

    main(args.did)