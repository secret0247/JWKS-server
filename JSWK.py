
#Tejas Sawdekar
#02/29/2024
from flask import Flask, request, jsonify
from datetime import datetime, timedelta
from Crypto.PublicKey import RSA
import jwt

app = Flask(__name__)


keys = {}       # store RSA key
 
def gen_rsa_key():          # generate RSA 
    #private_key = rsa_key.export_key()
    rsa_key = RSA.generate(2048)
    key_id = "key_" + str(len(keys) + 1)
    exp_time = datetime.utcnow() + timedelta(days=10)  # Expiry in 10 days
    keys[key_id] = {"RSA_key": rsa_key, "exp_time": exp_time}
    return key_id

# Function to serve JWKS endpoint
@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    jwks_keys = []
    present = datetime.utcnow()
    for key_id, key_info in keys.items():
        if key_info["exp_time"] > present:
            rsa_key = key_info["rsa_key"]
            jwks_keys.append({
                "kid": key_id,
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "n": rsa_key.n,
                "e": rsa_key.e
            })
    return jsonify(keys=jwks_keys)

# Function to authenticate and issue JWTs
@app.route('/auth', methods=['POST'])
def auth():
    expired = request.args.get('exp_time')
    if expired:
        key_id = list(keys.keys())[0]  # Choose the first key for expired token
    else:
        key_id = gen_rsa_key()
    rsa_key = keys[key_id]["rsa_key"]
    exp_time = keys[key_id]["exp_time"]
    payload = {'exp': exp_time, 'sub': 'fake_user'}
    token = jwt.encode(payload, rsa_key, algorithm='RS256', headers={'kid': key_id})
    return jsonify(token=token)

if __name__ == '__main__':
    app.run(port=8080)
