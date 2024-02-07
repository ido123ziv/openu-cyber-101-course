import string
import random

from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

PORT_FILE = "port.info"
MESSAGE_SERVER_FILE = "msg.info"
PROTOCOL_VERSION = 24


def get_port():
    try:
        with open(PORT_FILE, 'r') as portfile:
            port = portfile.readline().strip()
            if port:
                return port
    except Exception as e:
        print(str(e))
        print("Going back to default port: 1256")
    finally:
        return 1256


# get_message_server_details. defaults to read but can write to it
# TODO add options to write to this file, create a new one maybe
def get_message_servers(write=False):
    msg_srv = {}
    flag = 'r'
    if write:
        flag = 'r+'
    try:
        with open(MESSAGE_SERVER_FILE, flag) as msg_srv_file:
            message_server = msg_srv_file.readlines()
            msg_srv["ip"] = message_server[0].split(':')[0]
            msg_srv["port"] = message_server[0].split(':')[1].strip()
            msg_srv["name"] = message_server[1].strip()
            msg_srv["uuid"] = message_server[2].strip()
            msg_srv["key"] = message_server[3].strip()
            return msg_srv
    except Exception as e:
        print(str(e))
        print("Can't open message server details")
        return default_msg_server()


def get_version():
    return PROTOCOL_VERSION


def default_msg_server():
    return {
        "ip": "127.0.0.1",
        "port": 1235,
        "name": "Printer 20",
        "uuid": "64f3f63985f04beb81a0e43321880182",
        "key": "MIGdMA0GCSqGSIb3DQEBA"
    }


def create_password_sha(password: str):
    """
    creates a sha256 from a given password
    :param password: string representing a password
    :return: a sha256 of the password
    """
    sh = SHA256.new()
    sh.update(bytes(password, encoding='utf-8'))
    return sh.hexdigest()


def encrypt_aes(aes_key, nonce, data):
        """
        encrypts a given data using aes key and nonce.
        :param aes_key: AES Symmetric Key in used.
        :param data: data to encrypt.
        :param nonce: random value created by the client.
        :return: encrypted data as bytes object.
        """
        ciphertext = aes_key.encrypt(pad(data, AES.block_size))
        return base64.b64encode(nonce + ciphertext)


def decrypt_aes(encrypted_data, key):
    """
    decrypts a given encrypted data using aes key.
    :param encrypted_data: data to decript. 
    :param key: AES Symmetric Key in used.
    :return: decrypted data as byte string.
    """
    data = base64.b64decode(encrypted_data)
    iv, ciphertext = data[:16], data[16:]
    cipher = AES.new(key, iv, AES.MODE_CBC)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_data


def create_nonce():
    """returns random 8 bytes value as nonce."""
    return get_random_bytes(8)


def create_iv():
    """returns random 16 bytes value as IV."""
    return get_random_bytes(16)


def name_generator():
    name = ''.join(random.choices(string.ascii_lowercase, k=random.randint(3, 5)))
    password = name[0].upper() + name[0].lower() + "123456!"
    return {"name": name, "password": password}

