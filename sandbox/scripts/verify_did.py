import hashlib
import base58
import ecdsa
import requests
import json
import dns.resolver
import dns.message
import dns.rdatatype
import dns.rdata

import requests
from OpenSSL import crypto
import ssl, socket


from secp256k1 import PrivateKey, PublicKey
from binascii import unhexlify, hexlify

from datetime import datetime
from urllib.parse import urlparse, parse_qs

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

import logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def get_tls_public_key(host, port=443):
    # Create a socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Create an SSL context without certificate verification
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    # Wrap the socket with SSL
    wrapped_socket = context.wrap_socket(sock, server_hostname=host)

    # Connect and retrieve the certificate
    wrapped_socket.connect((host, port))
    der_cert = wrapped_socket.getpeercert(True)
    wrapped_socket.close()

    # Convert to X509
    x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, der_cert)

    # Extract the public key
    public_key = x509.get_pubkey()
    public_key_pem = crypto.dump_publickey(crypto.FILETYPE_PEM, public_key)
    # print(public_key_pem)

    public_key_obj = serialization.load_pem_public_key(
        public_key_pem,
        backend=default_backend()
    )

    public_key_bytes = public_key_obj.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return hexlify(public_key_bytes).decode().upper()




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

def did_doc_handler(did_doc):
    #This function inspects the did_doc to determine which keys to use for verifcatin

    logging.debug("did doc handler")

    try:
        did_doc['header']['type']
    except:
        pass

    return True

def query_tlsa_record(domain, usage, selector, matching_type, subdomain="_did."):
    resolver = dns.resolver.Resolver()
    resolver.use_dnssec = True
    resolver.nameservers = ['8.8.8.8']
    
    try:
        query_domain = subdomain + domain
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

def query_did_dns_record(domain):
    resolver = dns.resolver.Resolver()
    resolver.use_dnssec = True
    resolver.nameservers = ['8.8.8.8']
    resolver.use_edns = True

    try:
        query_domain = '_did.' + domain        
        response = resolver.resolve(query_domain, 'TXT')
        certificate_key= str(response[0]).strip("\"")
        logging.debug(f"OK: query_domain {query_domain} certificate_key {certificate_key}")
        return certificate_key

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

    # Start with verification result as true and toggle to false if there is any error
    verification_result = True
    # Step 1 get the did doc

    try:
        did_doc = download_did_document(did_web)
        
        logging.debug("OK:" + " Retrieved DID doc!")
    except:
        logging.debug("ERROR:" + "Did not retrieve DID doc")
        
    
    # Step 2 need to figure out what type of did we are handling
    # This can be determined by inspecting the did doc
    # Not sure if I need this function yet
    # did_doc_handler(did_doc)

    # Step XX: Extract dns domain from did:web identifier

    domain = urlparse(did_web_to_url(did_web)).hostname
    alg = "not specified"

    # Step XX: inspect did doc to determine how to lookup be
    # pubkey in TXT record
    # TLSA in TLSA record
    # if there is header, we know it is a pubkey, otherwise TLSA record

    try:
        # Parameters for looking up TLSA record
        usage = 3           # indicates domain issued certificate
        selector = 1        # specifies only public key is used
        matching_type = 0   # indicates public key
        tls_dns_public_key_record = query_tlsa_record(domain,usage,selector,matching_type, "_443._tcp.")
        tls_dns_public_key = hexlify(tls_dns_public_key_record.cert).decode()
        tls_website_public_key = get_tls_public_key(domain)
        # print("web and dns", tls_dns_public_key,tls_website_public_key)
        assert tls_dns_public_key.upper() == tls_website_public_key.upper()
        logging.debug(f"OK: DNS and Website TLS certificates MATCH!")

    except:
        logging.debug(f"ERROR: DNS and Website certificates DO NOT MATCH!")
        verification_result = False

    # header = did_doc.get('header', None)
    try:
        header = did_doc['header']
    except:
        header = None

    if header:
        
        alg = header['verificationMethod'][0]['type']

        # Step XX: Get public key from DNS/DNSSEC record
        # Change into a more generic function
        if header['dnsType'] == 'txt':   
            logging.debug("OK: look for DNS TXT record for verification")         
            certificate_key = query_did_dns_record(domain)
            logging.debug(f"OK: DNS TXT record: {certificate_key}, {alg}")
            

        elif header['dnsType'] == 'tlsa':
            logging.debug(f"OK: dnsType tlsa record")
            # Parameters for looking up TLSA record
            usage = 3           # indicates domain issued certificate
            selector = 1        # specifies only public key is used
            matching_type = 0   # indicates public key

            tlsa_record = query_tlsa_record(domain, usage, selector, matching_type)
            
            if tlsa_record:
                public_key = tlsa_record.cert
                # print(f"public key from _did.{domain} TLSA record: ", hexlify(public_key).decode())
                signature = did_doc["signature"]
                # print("signature from did doc: ", signature)
                # del did_doc["header"]
                del did_doc["signature"]
                # print(json.dumps(did_doc, indent=4))
                msg = json.dumps(did_doc)
                signature_bytes = unhexlify(signature)
                if verify_ecdsa_signature(signature_bytes, msg.encode(), public_key):
                    logging.debug("OK: Signature verified successfully.")
                    # Now we need to check if expired
                    exp = datetime.fromisoformat(did_doc['exp'])
                    current_time = datetime.utcnow()        
                    try:
                        assert current_time < exp
                        logging.debug("OK: DID doc not expired!")
                    except:            
                        logging.debug("ERROR: DID doc expired")
                        verification_result = False

                    # return True
                else:
                    logging.debug("ERRO: Signature verification failed.")
                    verification_result = False
                    
                # return False
            else:
                logging.debug("ERROR: No matching TLSA record found.")
                verification_result = False
            
            return verification_result

            
        
        else:
            # see issue 16 - the _cert can be deprecated
            certificate_key, certificate_path = query_cert_record(domain)
            logging.debug("OK: " + certificate_key + certificate_path)
   

        #TODO This code block needs to go up into dnsType "txt"
        if certificate_key:
            
            logging.debug("OK: _cert record: " + certificate_key)        
        else:
            logging.error("No matching cert record found.")
            verification_result = False
            # return False

        # Step 3: Extract signature, iss,and exp from did doc
        try:
            signature = did_doc['signature']
            exp = datetime.fromisoformat(did_doc['exp'])
            
        except:
            logging.error("ERROR: Not a valid did doc!")
            verification_result = False
            # return False
        
        logging.debug("OK: Valid did doc")
        # Remove sections that are not signed

        # Step 4: Remove non-payload data for signature verification
        
        # del did_doc["header"]
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
        current_time = datetime.utcnow()
        
        try:
            assert current_time < exp
        except:
            logging.debug("OK: DID doc not expired.")
            verification_result = False
        

        # Step 7: Verify the did doc
        # We can determine from alg what curve/algorithm to use
        logging.debug(f"OK: did doc signing and verification algorithm: {alg}")
        public_key_obj = PublicKey(unhexlify(certificate_key), raw=True)
        sig_obj = public_key_obj.ecdsa_deserialize(unhexlify(signature.encode()))

    else: # This is the fallback which assumes a TLSA record
        logging.debug("INFO: Fallback to original method of TLSA and proof")
        logging.debug("OK: look for TLSA record for verification")
        # Parameters for looking up TLSA record
        usage = 3
        selector = 1
        matching_type = 0

        tlsa_record = query_tlsa_record(domain, usage, selector, matching_type)

        if tlsa_record:
            public_key = tlsa_record.cert
            print(f"public key from TLSA _did.{domain} record: ", hexlify(public_key))
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
            logging.debug("ERROR: No matching TLSA record found.")
            verification_result = False
        
        return verification_result
       
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

    logging.debug("starting...")

    # verify_did confirms if it is a high assurance did
    
     
    # did_web = 
   
    did_test = [    "did:web:trustroot.ca",
                    "did:web:credentials.trustroot.ca",
                    "did:web:community.trustroot.ca",
                    "did:web:trbouma@trustroot.ca",
                    "did:web:trbouma@credentials.trustroot.ca",
                    "did:web:trbouma@community.trustroot.ca"
                    
                    
                      
                ]    

    
    for each_did in did_test:
        print(each_did)
        result = verify_did(each_did)
        print(f"verify did {each_did}:", result)
        


