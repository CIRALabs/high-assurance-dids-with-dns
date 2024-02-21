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
from binascii import unhexlify, hexlify

from urllib.parse import urlparse, parse_qs
import ecdsa
from ecdsa import SigningKey

from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
import logging

from datetime import datetime, timedelta

from .config import Settings
from .verify import did_web_to_url, download_did_document, query_tlsa_record

# Initialize issuer database
issuer_db = {}
with open('app/data/issuers.json', "r") as file:
    issuer_data = json.load(file)
    
for each in issuer_data['issuers']:
    domain = each['domain']
    del each['domain']
    issuer_db[domain] = each



# Initialize user database
user_db = {}
with open('app/data/users.json', "r") as file:
    user_data = json.load(file)
for each in user_data['users']:
    user_db[each['user']] = [each['pubkey']]



def query_pubkey_record(domain):
    resolver = dns.resolver.Resolver()
    resolver.use_dnssec = False
    resolver.nameservers = ['8.8.8.8']
    resolver.use_edns = False

    try:
        query_domain = '_pubkey.' + domain 
        print(query_domain)       
        response = resolver.resolve(query_domain, 'TXT')
        print(response[0])
        return response[0]

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
    resolver = dns.resolver.Resolver()
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
    
templates = Jinja2Templates(directory="templates")

settings = Settings()



# print(settings.PRIVATE_KEY, settings.PUBLIC_KEY)

# private_key = PrivateKey(unhexlify(settings.PRIVATE_KEY))
# public_key_hex = private_key.pubkey.serialize().hex()



app = FastAPI(  title=settings.PROJECT_TITLE,
                description=settings.PROJECT_DESCRIPTION,
                version="0.0.1"
)


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    # return {"message": "Hello World"}
    return templates.TemplateResponse(  "home.html", 
                                      { "request" : request,
                                        "settings" : settings
                                         })


@app.get("/.well-known/did.json", tags=["public"])
def get_did_doc(request: Request):

   

    did_domain = request.url.hostname
    if did_domain == "127.0.0.1":
        did_domain = 'trustroot.ca'

    print(issuer_db[did_domain]['dnsType'])
    if issuer_db[did_domain]['dnsType'] == "tlsa":
        privkey_pem_file = f"app/data/keys/{did_domain}/privkey.pem"
        print(privkey_pem_file)
        with open(privkey_pem_file, 'rb') as key_file:
            private_key_pem = key_file.read()
        tlsa_private_key = SigningKey.from_pem(private_key_pem)
        tlsa_record = query_tlsa_record(did_domain,3,1,0)
        certificate_key = hexlify(tlsa_record.cert).decode()

        public_key = tlsa_private_key.get_verifying_key()
        public_key_pem = public_key.to_pem()
        public_key_bytes = hexlify(public_key.to_string()).decode()
        print("public key:", public_key_bytes)
        print("public key pem:", public_key_pem.decode())
    else:
        try:
            certificate_key = query_did_dns_record(did_domain)
            private_key = PrivateKey(unhexlify(issuer_db[did_domain]['privkey']))
        except:
            return {"error": "pubkey record does not exist!"}


        print("ISSUER", issuer_db[did_domain]['privkey'])
        
        public_key_hex = private_key.pubkey.serialize().hex()
        print(public_key_hex, certificate_key)

        # Do a check against the 
        try:
        
            assert certificate_key == public_key_hex
        except:
            return {"error": "issuer record do not match dns record!"}
    
    
    current_time_int = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f%z")
    expiry_time_int = (datetime.utcnow() + timedelta(seconds=settings.TTL)).strftime("%Y-%m-%dT%H:%M:%S.%f%z")

    did_doc = {
                "@context": 
                    ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/secp256k1recovery-2020"], 

                

                "id":       f"did:web:{did_domain}",                 
                "sub":      f"did:web:{did_domain}", 
                "verificationMethod": 
                    [{
                        "id": f"did:web:{did_domain}#key-dnstlsa",
                        "controller": f"did:web:{did_domain}",
                        "type": issuer_db[did_domain]['alg'],
                        "publicKeyHex": certificate_key
                     }
                    ]              
    }

    # create a copy for signing
    did_doc_to_sign = did_doc.copy()

    # remove header, treat everything else as payload

    # We'll keep in the header for now
    # del(did_doc_to_sign['header'])

    msg = json.dumps(did_doc_to_sign)

    # Generate signature based on dnsType

    if issuer_db[did_domain]['dnsType'] == "tlsa":
        signature = tlsa_private_key.sign(msg.encode(),hashfunc=hashlib.sha256 )
        sig_hex = hexlify(signature).decode()
        
    else:
        sig = private_key.ecdsa_sign(msg.encode())    
        sig_hex= private_key.ecdsa_serialize(sig).hex()
    # add in resulting signature to the original did doc
    # did_doc["signature"] = sig_hex

    did_doc["proof"] =  {

            "id": f"did:web:{did_domain}",
            "type": "DataIntegrityProof",
            "dnsType": issuer_db[did_domain]['dnsType'],
            "proofPurpose": "assertionMethod",              
            "verificationMethod": f"did:web:{did_domain}#key-dnstlsa",                       
            "created": current_time_int,
            "expires" : expiry_time_int, 
            "cryptosuite": issuer_db[did_domain]['alg'], 
            "proofValue": sig_hex
  }


    return did_doc


@app.get("/{entity_name}/did.json",tags=["public"])
def get_user_did_doc(entity_name: str, request: Request):
    try:
        entity_iss = user_db[entity_name]
        entity_alg = "secp256k1"
        ## Lookup pubkey
    except:
        return {"error": "issuing entity does not exist"}
    

    did_domain = request.url.hostname
    if did_domain == "127.0.0.1":
        did_domain = 'trustroot.ca'

    print(issuer_db[did_domain]['dnsType'])
    if issuer_db[did_domain]['dnsType'] == "tlsa":
        privkey_pem_file = f"app/data/keys/{did_domain}/privkey.pem"
        print(privkey_pem_file)
        with open(privkey_pem_file, 'rb') as key_file:
            private_key_pem = key_file.read()
        tlsa_private_key = SigningKey.from_pem(private_key_pem)
        tlsa_record = query_tlsa_record(did_domain,3,1,0)
        certificate_key = hexlify(tlsa_record.cert).decode()

        public_key = tlsa_private_key.get_verifying_key()
        public_key_pem = public_key.to_pem()
        public_key_bytes = hexlify(public_key.to_string()).decode()
        print("public key:", public_key_bytes)
        print("public key pem:", public_key_pem.decode())
    else:
        try:
            certificate_key = query_did_dns_record(did_domain)
            private_key = PrivateKey(unhexlify(issuer_db[did_domain]['privkey']))
        except:
            return {"error": "pubkey record does not exist!"}


        print("ISSUER", issuer_db[did_domain]['privkey'])
        
        public_key_hex = private_key.pubkey.serialize().hex()
        print(public_key_hex, certificate_key)

        # Do a check against the 
        try:
        
            assert certificate_key == public_key_hex
        except:
            return {"error": "issuer record do not match dns record!"}
    
    current_time_int = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f%z")
    expiry_time_int = (datetime.utcnow() + timedelta(seconds=settings.TTL)).strftime("%Y-%m-%dT%H:%M:%S.%f%z")

    did_doc = {
                "@context": 
                    ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/secp256k1recovery-2020"], 

                

                "id":       f"did:web:{did_domain}:{entity_name}",                
                "sub":      f"did:web:{did_domain}:{entity_name}",  
                "verificationMethod": 
                    [{
                        "id": f"did:web:{did_domain}:{entity_name}",
                        "controller": f"did:web:{did_domain}:{entity_name}",
                        "type": entity_alg,
                        "publicKeyHex": entity_iss
                     },
                     {
                        "id": f"did:web:{did_domain}#key-dnstlsa",
                        "controller": f"did:web:{did_domain}",
                        "type": issuer_db[did_domain]['alg'],
                        "publicKeyHex": certificate_key
                     }
                    ]              
               
    }

    # create a copy for signing
    did_doc_to_sign = did_doc.copy()

    # remove header, treat everything else as payload

    
    # del(did_doc_to_sign['header'])

    msg = json.dumps(did_doc_to_sign)
    # Generate signature based on dnsType

    if issuer_db[did_domain]['dnsType'] == "tlsa":
        signature = tlsa_private_key.sign(msg.encode(),hashfunc=hashlib.sha256 )
        sig_hex = hexlify(signature).decode()
        
    else:
        sig = private_key.ecdsa_sign(msg.encode())    
        sig_hex= private_key.ecdsa_serialize(sig).hex()
    # add in resulting signature to the original did doc
    # did_doc["signature"] = sig_hex

    did_doc["proof"] =  {

            "id": f"did:web:{did_domain}",
            "type": "DataIntegrityProof",
            "dnsType": issuer_db[did_domain]['dnsType'],
            "proofPurpose": "assertionMethod",              
            "verificationMethod": f"did:web:{did_domain}#key-dnstlsa",                       
            "created": current_time_int,
            "expires" : expiry_time_int, 
            "cryptosuite": issuer_db[did_domain]['alg'], 
            "proofValue": sig_hex
  }

    return did_doc


@app.get("/verifydid{did}",tags=["public"])
def get_verify_did(did: str, request: Request):
    checks = {}

    #prepend did:web if not supplied
    did = "did:web:" + did if did[:7] != 'did:web' else did

    # get validat url

    # Step 1 : Get web url
    did_web_url = did_web_to_url(did)
    checks['did_web_url'] = did_web_url

    # Step 2: Get did doc
    did_doc = download_did_document(did)
    
    if did_doc == None:
        checks['did_doc'] = "No did doc!"
        return {"did": did, "checks": checks }
    else:
        checks['did_doc'] = did_doc

    #Step 3: determine type of did doc and which DNS rer

    if did_doc.get("header", None):
        checks["dnsType"] = did_doc['header']['dnsType']
        
    else:
        checks['dnsType'] = 'not defined'

    return {"did": did, "checks": checks }