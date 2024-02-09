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

def verify_did_doc(did_doc, public_key):

    signature = did_doc['signature']
    iss = did_doc['iss']
    exp = did_doc['exp']
    iat = did_doc['iat']

    # Remove sections that are not signed
    del did_doc["@context"]
    del did_doc["header"]
    del did_doc["signature"]
    # Dump resulting for signature check
    message = json.dumps(did_doc)

    # check to see if right key
    try:
        assert iss == public_key
    except:
        return False
    
    # check to see if did doc is expired
    current_time_int = int(datetime.utcnow().timestamp())
    
    try:
        assert current_time_int < exp
    except:
        return False

    public_key_obj = PublicKey(unhexlify(public_key), raw=True)
    sig_obj = public_key_obj.ecdsa_deserialize(unhexlify(signature.encode()))
    
    
    return public_key_obj.ecdsa_verify(message.encode(), sig_obj, digest=hashlib.sha256)
 
    

def download_did_document(did_web):
    did_web_url = 'https://' + did_web.split(':')[-1] + '/.well-known/did.json'
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
    domain = "lncreds.ca"
    did_web = "did:web:lncreds.ca"
    usage = 3
    selector = 1
    matching_type = 0

   
    # Independently look up the pubkey in DNS
    pubkey_record = query_pubkey_record(domain)

    if pubkey_record:
        pubkey_record_str = str(pubkey_record).strip("\"")
        print(pubkey_record_str)
        
    else:
        print("No matching pubkey record found.")

    did_doc = download_did_document(did_web)
    print(did_doc)


    # verify did doc using pubkey that was looked up on DNS
    result = verify_did_doc(did_doc, pubkey_record_str)

    print("verify did doc", result)

