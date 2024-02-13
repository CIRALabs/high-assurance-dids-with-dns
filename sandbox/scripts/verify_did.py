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

def did_web_to_url(did_web):
    # Routine to transform did_web into corresponding url

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

def did_doc_handler(did_doc):
    #This function inspects the did_doc to determine which keys to use for verifcatin

    logging.debug("did doc handler")

    try:
        did_doc['header']['type']
    except:
        pass

    return True

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
        query_domain = '_cert.' + domain        
        response = resolver.resolve(query_domain, 'TXT')

        
        return response[0]

    except dns.resolver.NoAnswer:
        return None
    


    except dns.resolver.NoAnswer:
        return None
    
def query_cert_record(domain):
    resolver = dns.resolver.Resolver()
    resolver.use_dnssec = True
    resolver.nameservers = ['8.8.8.8']
    resolver.use_edns = True

    try:
        query_domain = '_cert.' + domain        
        response = resolver.resolve(query_domain, 'TXT')
        certificate_record= str(response[0]).strip("\"")
        parsed_record = urlparse(certificate_record)
        parsed_dict = parse_qs(parsed_record.query)
        certificate_key = parsed_dict['kid'][0].strip().replace("\"",'')
        certificate_path = parsed_record.path
        print(certificate_key,certificate_path)
        return certificate_key, certificate_path, 

    except dns.resolver.NoAnswer:
        return None, None

def verify_signature(signature, message, public_key):
    # Signature verfication routuine for pubkey
    public_key_obj = PublicKey(unhexlify(public_key), raw=True)
    sig_obj = public_key_obj.ecdsa_deserialize(unhexlify(signature.encode()))
    
    return public_key_obj.ecdsa_verify(message.encode(), sig_obj, digest=hashlib.sha256)

def verify_ecdsa_signature(signature, message, public_key):
    # Signature verfication routuine for TLSA record
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

def verify_did(did_web):

    # Step 1 get the did doc

    try:
        did_doc = download_did_document(did_web)
        
        logging.debug("OK:" + json.dumps(did_doc, indent=4))
    except:
        return False
    
    # Step 2 need to figure out what type of did we are handling
    # This can be determined by inspecting the did doc
    # Not sure if I need this function yet
    # did_doc_handler(did_doc)

    # Step XX: Extract dns domain from did:web identifier

    domain = urlparse(did_web_to_url(did_web)).hostname

    # Step XX: inspect did doc to determine how to lookup be
    # pubkey in TXT record
    # TLSA in TLSA record
    # if there is header, we know it is a pubkey, otherwise TLSA record

    # header = did_doc.get('header', None)
    try:
        header = did_doc['header']
    except:
        header = None

    if header:
        logging.debug("OK: look for pubkey record for verification")

        # Step XX: Get public key from DNS/DNSSEC record
        # Change into a more generic function

        # pubkey_record = query_pubkey_record(domain)
        certificate_key, certificate_path = query_cert_record(domain)
        logging.debug("OK: " + certificate_key + certificate_path)
   

        if certificate_key:
            
            logging.debug("OK: _cert record: " + certificate_key)        
        else:
            logging.error("No matching cert record found.")
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
        # Note: iss is now the did instead of the pubkey, so this step is unnecessary
        # try:
        #     assert iss == pubkey_record_str
        # except:
        #    return False    
        # logging.debug("OK: Valid public key")
        # logging.debug(f"OK: _pubkey {pubkey_record_str} is same as iss: {iss}")

        # Step 6: Check to see if did doc is expired
        current_time_int = int(datetime.utcnow().timestamp())
        
        try:
            assert current_time_int < exp
        except:
            
            return False
        logging.debug("OK: DID doc not expired.")
        

        # Step 7: Verify the did doc
        public_key_obj = PublicKey(unhexlify(certificate_key), raw=True)
        sig_obj = public_key_obj.ecdsa_deserialize(unhexlify(signature.encode()))

    else: # This is for the TLSA record
        logging.debug("OK: look for TLSA record for verification")
        # Parameters for looking up TLSA record
        usage = 3
        selector = 1
        matching_type = 0

        tlsa_record = query_tlsa_record(domain, usage, selector, matching_type)

        if tlsa_record:
            public_key = tlsa_record.cert
            print("public key from TLSA record: ", public_key)
            signature = did_doc["proof"]["proofValue"]
            print("signature from did doc: ", signature)
            del did_doc["proof"]
            print(json.dumps(did_doc, indent=4))
            msg = json.dumps(did_doc)
            if verify_ecdsa_signature(base58.b58decode(signature), msg.encode(), public_key):
                print("Signature verified successfully.")
                return True
            else:
                print("Signature verification failed.")
                return False
        else:
            print("No matching TLSA record found.")
            return False
        
        return False
       
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

    # verify_did confirms if it is a high assurance did
    
     
    # did_web = 
   
    did_test = [    "did:web:lncreds.ca",
                    "did:web:lncache.ca:trbouma",
                    "did:web:lncreds.ca:trbouma",
                    "did:web:trustregistry.ca",
                    "did:web:lncache.ca:examplecorp",
                    "did:web:trustroot.ca:trbouma",
                    "did:web:credentials.trustroot.ca:examplecorp"

                ]    

    
    for each_did in did_test:
        print(each_did)
        result = verify_did(each_did)
        print(f"verify did {each_did}:", result)

    
