import hashlib
import base58
import ecdsa
import requests
import json
import dns.resolver
import dns.message
import dns.rdatatype
import dns.rdata

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

def verify_signature(signature, message, public_key):
    try:
        public_key = ecdsa.keys.VerifyingKey.from_der(public_key)
    except Exception as e:
        print(f"Error loading key: {e}")
        return False
    
    try:
        assert public_key.verify(signature, message, hashfunc=hashlib.sha256)
    except Exception as e:
        print(f"Error verifying signature: {e}")
        return False
    return True

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
    domain = "trustregistry.ca"
    usage = 3
    selector = 1
    matching_type = 0

    did_web = "did:web:trustregistry.ca"
    did_doc = download_did_document(did_web)
    
    tlsa_record = query_tlsa_record(domain, usage, selector, matching_type)
    if tlsa_record:
        public_key = tlsa_record.cert
        print("public key from TLSA record: ", public_key)
        signature = did_doc["proof"]["proofValue"]
        print("signature from did doc: ", signature)
        del did_doc["proof"]
        print(json.dumps(did_doc, indent=4))
        msg = json.dumps(did_doc)
        if verify_signature(base58.b58decode(signature), msg.encode(), public_key):
            print("Signature verified successfully.")
        else:
            print("Signature verification failed.")
    else:
        print("No matching TLSA record found.")