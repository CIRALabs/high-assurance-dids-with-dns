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

# create a fake_db for examples
fake_db = {}
fake_db['examplecorp'] =    {"iss": "026952458d60fa6eba68f8b50e15c4a6bf8c82a71b5502ef650ecd79c0c38a64f6"}
fake_db['xyzfoundation'] =  {"iss": "02300d753f822691b63c0c79134aa2069c946768600a3fb32b6078b8209e75d203"}
fake_db['localagency'] =    {"iss": "037de6dde204fb824af74be5421ad7104f02d14636402e53fdf26289ab9bac8911"}


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


@app.get("/.well-known/did.json", tags=["public"])
def get_did_doc(request: Request):

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
                    "typ":     "DID",
                    "alg":      "SECP256K1ECDSA",
                },

                "id":       f"did:web:{request.url.hostname}",
                "iss":      dns_pubkey_str, 
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

    # remove @context header, treat everything else as payload    
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
        entity_iss = fake_db[entity_name]['iss']
        ## Lookup pubkey
    except:
        return {"error": "issuing entity does not exit"}


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
                    "typ":     "DID",
                    "alg":      "SECP256K1ECDSA",
                },

                "id":       f"did:web:{request.url.hostname}:{entity_name}",
                "iss":      dns_pubkey_str, 
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

    # remove @context header, treat everything else as payload

    del(did_doc_to_sign['@context'])
    del(did_doc_to_sign['header'])

    msg = json.dumps(did_doc_to_sign)
    sig = private_key.ecdsa_sign(msg.encode())
    
    sig_hex= private_key.ecdsa_serialize(sig).hex()

    # add in resulting signature to the original did doc
    did_doc["signature"] = sig_hex


    return did_doc