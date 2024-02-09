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

from .config import Settings

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
        dns_pubkey = query_pubkey_record(request.url.hostname)

    dns_pubkey_str = str(dns_pubkey).strip("\"")

    print(dns_pubkey_str, public_key_hex)

    # Do a check against the 
    try:
        assert dns_pubkey_str == public_key_hex
    except:
        return {"error": "records do not match!"}
    
    did_doc = {
                
                "id": f"did:web:{request.url.hostname}",
                "pubkey": dns_pubkey_str                
               
    }

    msg = json.dumps(did_doc)
    sig = private_key.ecdsa_sign(msg.encode())
    
    sig_hex= private_key.ecdsa_serialize(sig).hex()

    did_doc["proof"] = sig_hex


    return did_doc