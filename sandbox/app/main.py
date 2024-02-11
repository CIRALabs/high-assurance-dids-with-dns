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

from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse

from datetime import datetime, timedelta

from .config import Settings

# Initialize issuer database
issuer_db = {}
with open('app/data/issuer.json', "r") as file:
    user_data = json.load(file)
for each in user_data['users']:
    issuer_db[each['issuer']] = [each['privkey']]


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


templates = Jinja2Templates(directory="templates")

settings = Settings()

print(settings.PRIVATE_KEY, settings.PUBLIC_KEY)

private_key = PrivateKey(unhexlify(settings.PRIVATE_KEY))
public_key_hex = private_key.pubkey.serialize().hex()



app = FastAPI(  title=settings.PROJECT_TITLE,
                description=settings.PROJECT_DESCRIPTION,
                version="0.0.1"
)




@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    # return {"message": "Hello World"}
    return templates.TemplateResponse(  "base.html", 
                                      { "request" : request,
                                        "settings" : settings
                                         })


@app.get("/.well-known/did.json",tags=["public"])
def get_did_doc(request: Request):

    ## Lookup pubkey
    if request.url.hostname == "127.0.0.1":
        dns_pubkey = query_pubkey_record("lncreds.ca")
    else:
        try:
            dns_pubkey = query_pubkey_record(request.url.hostname)
        except:
            return {"error": "pubkey record does not exist!"}

    dns_pubkey_str = str(dns_pubkey).strip("\"")

    print(dns_pubkey_str, public_key_hex)

    # Do a check against the 
    try:
        assert dns_pubkey_str == public_key_hex
    except:
        return {"error": "records do not match!"}
    
    current_time_int = int(datetime.utcnow().timestamp())
    expiry_time_int = int((datetime.utcnow() + timedelta(seconds=settings.TTL)).timestamp())

    did_doc = {
                "@context": 
                    ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/secp256k1recovery-2020"], 

                "header": {
                    "typ":     "pubkey",
                    "alg":      "secp256k1ecdsa",
                },

                "id":       f"did:web:{request.url.hostname}",
                "iss":      f"did:web:{request.url.hostname}", 
                "sub":      f"did:web:{request.url.hostname}",                
                "iat":      current_time_int,
                "exp":      expiry_time_int, 

                "verificationMethod": 
                    [{
                        "id": f"did:web:{request.url.hostname}",
                        "controller": f"did:web:{request.url.hostname}",
                        "type": "EcdsaSecp256k1RecoveryMethod2020",
                        "publicKeyHex": dns_pubkey_str
                     }
                    ]              
               
    }

    # create a copy for signing
    did_doc_to_sign = did_doc.copy()

    # remove header, treat everything else as payload

    
    del(did_doc_to_sign['header'])

    msg = json.dumps(did_doc_to_sign)
    sig = private_key.ecdsa_sign(msg.encode())
    
    sig_hex= private_key.ecdsa_serialize(sig).hex()

    # add in resulting signature to the original did doc
    did_doc["signature"] = sig_hex


    return did_doc

@app.get("/{entity_name}/did.json",tags=["public"])
def get_user_did_doc(entity_name: str, request: Request):
    

    try:
        entity_iss = user_db[entity_name]
        ## Lookup pubkey
    except:
        return {"error": "issuing entity does not exit"}
    

    ## Lookup pubkey
    if request.url.hostname == "127.0.0.1":
        dns_pubkey = query_pubkey_record("lncreds.ca")
    else:
        dns_pubkey = query_pubkey_record(request.url.hostname)

    dns_pubkey_str = str(dns_pubkey).strip("\"")

    print(dns_pubkey_str, public_key_hex)

    # Do a check against the 
    try:
        assert dns_pubkey_str == public_key_hex
    except:
        return {"error": "records do not match!"}
    
    current_time_int = int(datetime.utcnow().timestamp())
    expiry_time_int = int((datetime.utcnow() + timedelta(seconds=settings.TTL)).timestamp())

    did_doc = {
                "@context": 
                    ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/secp256k1recovery-2020"], 

                "header": {
                    "typ":     "pubkey",
                    "alg":      "secp256k1ecdsa",
                },

                "id":       f"did:web:{request.url.hostname}:{entity_name}",
                "iss":      f"did:web:{request.url.hostname}", 
                "sub":      f"did:web:{request.url.hostname}:{entity_name}",                
                "iat":      current_time_int,
                "exp":      expiry_time_int, 

                "verificationMethod": 
                    [{
                        "id": f"did:web:{request.url.hostname}:{entity_name}",
                        "controller": f"did:web:{request.url.hostname}:{entity_name}",
                        "type": "EcdsaSecp256k1RecoveryMethod2020",
                        "publicKeyHex": entity_iss
                     }
                    ]              
               
    }

    # create a copy for signing
    did_doc_to_sign = did_doc.copy()

    # remove header, treat everything else as payload

    
    del(did_doc_to_sign['header'])

    msg = json.dumps(did_doc_to_sign)
    sig = private_key.ecdsa_sign(msg.encode())
    
    sig_hex= private_key.ecdsa_serialize(sig).hex()

    # add in resulting signature to the original did doc
    did_doc["signature"] = sig_hex


    return did_doc