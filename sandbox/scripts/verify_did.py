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
from urllib.parse import urlparse

import logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def did_web_to_url(did_web):
    # Routine to transform did_web into corresponing url

    # replace colon with slash and encoded colon with colon

    did_web_url = did_web.replace(":", "/").replace('did/web/', "https://").replace('%3A',':')
    
    parsed_url = urlparse(did_web_url)
    if parsed_url.path == '':
        did_web_url = did_web_url + '/.well-known/did.json'
    else:
        did_web_url = did_web_url + "/did.json"    
    
    # strip out fragment and params
    
    did_web_url = did_web_url.replace('#'+ parsed_url.fragment,'').replace(parsed_url.query,'').replace('?','')    
    

    print("did_web_url:", did_web_url)

    # did_web_url =     'https://' + did_web.split(':')[-1] + '/.well-known/did.json'
    return did_web_url

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


def query_txt_record(domain):
    resolver = dns.resolver.Resolver()
    resolver.use_dnssec = True
    resolver.nameservers = ['8.8.8.8']
    resolver.use_edns = True

    try:
        query_domain = '_pubkey.' + domain        
        response = resolver.resolve(query_domain, 'TXT')
        
        return response[0]

    except dns.resolver.NoAnswer:
        return None
    
def query_pubkey_record(domain):
    resolver = dns.resolver.Resolver()
    resolver.use_dnssec = True
    resolver.nameservers = ['8.8.8.8']
    resolver.use_edns = True

    try:
        query_domain = '_pubkey.' + domain        
        response = resolver.resolve(query_domain, 'TXT')
        
        return response[0]

    except dns.resolver.NoAnswer:
        return None

def verify_signature(signature, message, public_key):

    public_key_obj = PublicKey(unhexlify(public_key), raw=True)
    sig_obj = public_key_obj.ecdsa_deserialize(unhexlify(signature.encode()))
    
    
    return public_key_obj.ecdsa_verify(message.encode(), sig_obj, digest=hashlib.sha256)

def verify_did(did_web):

    # Step 1 get the did doc

    try:
        did_doc = download_did_document(did_web)
        
        logging.debug("OK:" + json.dumps(did_doc, indent=4))
    except:
        return False
    
    # Step 2 need to figure out what type of did we are handling
    # This can be determined by inspecting the did doc

    # Step XX: Extract dns domain from did:web identifier

    domain = urlparse(did_web_to_url(did_web)).hostname



    # Step XX: Get public key from DNS/DNSSEC record
    # Change into a more generic function
    
    pubkey_record = query_pubkey_record(domain)
   

    if pubkey_record:
        pubkey_record_str = str(pubkey_record).strip("\"")
        logging.debug("OK: _pubkey record: " + pubkey_record_str)        
    else:
        logging.error("No matching pubkey record found.")
        return False

    # Step 3: Extract signature, iss,and exp from did doc
    try:
        signature = did_doc['signature']
        iss = did_doc['iss']
        exp = did_doc['exp']
        
    except:
        logging.error("Not a valid did doc!")
        return False
    
    logging.debug("OK: Valid did doc")
    # Remove sections that are not signed

    # Step 4: Remove non-payload data for signature verification
    
    del did_doc["header"]
    del did_doc["signature"]
    # Dump resulting for signature check
    message = json.dumps(did_doc)

    #  Step 5: Check to see if iss key is the same as from DNS
    try:
        assert iss == pubkey_record_str
    except:
        return False
    
    logging.debug("OK: Valid public key")

    # Step 6: Check to see if did doc is expired
    current_time_int = int(datetime.utcnow().timestamp())
    
    try:
        assert current_time_int < exp
    except:
        return False
    logging.debug("OK: DID doc not expired.")
    logging.debug(f"OK: _pubkey {pubkey_record_str} is same as iss: {iss}")

    # Step 7: Verify the did doc
    public_key_obj = PublicKey(unhexlify(pubkey_record_str), raw=True)
    sig_obj = public_key_obj.ecdsa_deserialize(unhexlify(signature.encode()))
        
    return public_key_obj.ecdsa_verify(message.encode(), sig_obj, digest=hashlib.sha256)
 



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
        
if __name__ == "__main__":

    # verify_did confirms whether it is a high assurance did
    
    did_web = "did:web:lncreds.ca:xyzfoundation"  
    # did_web = "did:web:trustregistry.ca"
   
    
    result = verify_did(did_web)
    print("verify did:", result)


