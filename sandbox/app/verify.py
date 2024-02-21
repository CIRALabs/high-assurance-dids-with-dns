import hashlib
import base58
import ecdsa
import requests
import json
import dns.resolver
import dns.message
import dns.rdatatype
import dns.rdata

from secp256k1 import PrivateKey, PublicKey
from binascii import unhexlify

from datetime import datetime
from urllib.parse import urlparse, parse_qs

import logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# DID handling verification functions



def did_web_to_url(did_web):
    # Routine to transform did_web into corresponding url

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
    

    
    return did_web_url

def download_did_document(did_web):

    did_web_url = did_web_to_url(did_web)
    try:
        response = requests.get(did_web_url)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Failed to download DID document. Status code: {response.status_code}")
            return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None
    
def query_tlsa_record(domain, usage, selector, matching_type):
    resolver = dns.resolver.Resolver()
    resolver.use_dnssec = True
    resolver.nameservers = ['8.8.8.8']
    
    try:
        query_domain = '_did.' + domain
        response = resolver.resolve(query_domain, 'TLSA')

        for rdata in response:
            if (rdata.usage == usage and
                rdata.selector == selector and
                rdata.mtype == matching_type):
                return rdata
    except dns.resolver.NoAnswer:
        return None