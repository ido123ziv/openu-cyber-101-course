import json
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

with open("data.json", 'r') as data_json:
    json_input = json.load(data_json)

with open("key.pem", 'r') as data_key:
    bytes_key = data_key.read()
    key = b64decode(bytes_key)

# We assume that the key was securely shared beforehand
try:
    b64 = json.loads(json_input)
    iv = b64decode(b64['iv'])
    ct = b64decode(b64['ciphertext'])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    print("The message was: ", pt)
except (ValueError, KeyError):
    print("Incorrect decryption")