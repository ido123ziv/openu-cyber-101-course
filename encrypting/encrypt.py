import json
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

data = b"secret"
key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_CBC)
ct_bytes = cipher.encrypt(pad(data, AES.block_size))
iv = b64encode(cipher.iv).decode('utf-8')
ct = b64encode(ct_bytes).decode('utf-8')
result = json.dumps({'iv': iv, 'ciphertext': ct})
print(result)

with open("data.json", 'w') as data_json:
    json.dump(result, data_json, indent=4)

with open("key.pem", 'w') as data_key:
    data_key.write(b64encode(key).decode('utf-8'))
