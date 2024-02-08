from fastapi import FastAPI, Request

app = FastAPI()




@app.get("/")
async def root():
    return {"message": "Hello World"}


@app.get("/.well-known/did.json",tags=["public"])
def get_did_doc(request: Request):
    
    
    pubkey = "123abc"

    

    did_doc = {
                "@context": ["https://www.w3.org/ns/did/v1", 
                "https://w3id.org/security/suites/secp256k1recovery-2020/v2"],
                "id": f"did:web:{request.url.hostname}",
                 "verificationMethod": [{
                    "id": f"did:web:{request.url.hostname}",
                    "pubkey": pubkey
                    
                   
                    }],
                "authentication": [
                    f"did:web:{request.url.hostname}"
                ]
}

    return did_doc