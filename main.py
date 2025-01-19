from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import base64
import json

from jwcrypto import jwk, jwe as jwe_module  
from jwcrypto.common import json_encode

app = FastAPI()

origins = [
    "http://127.0.0.1:8000",
    "http://localhost:8000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
    
    if(len(result_array)==6):
        user_data = { 
            "federation": { 
                "userId" : result_array[0], 
                "email" : result_array[1], 
                "termsAccepted" : False 
            },
            "userInfo": { 
                "person" : { "personName" : { "givenName" : result_array[2], "lastName" : result_array[3], "secondLastName" : result_array[4] } }, 
                "userEntities" : { "userId" : result_array[0], "entity" : { "entityId" : result_array[5] } }, 
                "userNotificationsGroups" : { "mandatory" : [ "student" ] } 
                } 
            }
    elif(len(result_array)==1):
        user_data = { "federation": { "userId" : result_array[0] } }
    else:
        user_data = {}

    token = create_jwe_token(user_data)

    return { "data": token, "value" : user_data}