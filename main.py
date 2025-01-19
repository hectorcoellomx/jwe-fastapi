from fastapi import FastAPI
import base64
import json

from jwcrypto import jwk, jwe as jwe_module  
from jwcrypto.common import json_encode

app = FastAPI()

def create_jwe_token(user_data):

    key_path = 'unach-public-key.pem'
    
    with open(key_path, 'rb') as key_file:
        public_key_pem = key_file.read()

    key = jwk.JWK.from_pem(public_key_pem)
    payload = json.dumps(user_data)

    jwetoken = jwe_module.JWE(payload.encode('utf-8'), json_encode({"alg": "RSA-OAEP-256", "enc": "A256GCM"}))  
    jwetoken.add_recipient(key)  
    enc = jwetoken.serialize(compact=True)

    return enc



@app.get("/")
async def root():
    return {"message": "Hello World"}

@app.get("/jwe/{data}")
async def jwe(data):
    decoded_string = base64.b64decode(data).decode('utf-8')
    result_array = decoded_string.split(',')
    
    if(len(result_array)==1):
        user_data = { "federation": { "userId" : result_array[0] } }
    else:
        user_data = { "federation": { "userId" : result_array[0] } }

    token = create_jwe_token(user_data)

    return { "data": token, "value" : result_array}