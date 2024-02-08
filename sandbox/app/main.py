import hashlib
import base58
import ecdsa
import requests
import json
import dns.resolver
import dns.message
import dns.rdatatype
import dns.rdata

from fastapi import FastAPI, Request

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


app = FastAPI(  title="High Assurance did:web",
                description="Demonstration web site",
                version="0.0.1"
)




    





@app.get("/")
async def root():
    return {"message": "Hello World"}


@app.get("/.well-known/did.json",tags=["public"])
def get_did_doc(request: Request):

    ## Lookup pubkey
    if request.url.hostname == "127.0.0.1":
        pubkey = query_pubkey_record("lncreds.ca")
    else:
        pubkey = query_pubkey_record(request.url.hostname)

    pubkey_str = str(pubkey).strip("\"")
    
    did_doc = {
                "@context": ["https://www.w3.org/ns/did/v1", 
                "https://w3id.org/security/suites/secp256k1recovery-2020/v2"],
                "id": f"did:web:{request.url.hostname}",
                 "verificationMethod": [{
                    "id": f"did:web:{request.url.hostname}",
                    "pubkey": pubkey_str
                    
                   
                    }],
                "authentication": [
                    f"did:web:{request.url.hostname}"
                ]
    }


    return did_doc