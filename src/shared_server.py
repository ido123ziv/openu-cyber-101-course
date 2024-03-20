import os

from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode


FOLDER_NAME = os.path.dirname(os.path.abspath(__file__))
PORT_FILE = f"{FOLDER_NAME}/port.info"
MESSAGE_SERVER_FILE = f"{FOLDER_NAME}/msg.info"
CLIENT_FILE = f"{FOLDER_NAME}/clients.info"
ERROR_MESSAGE = "Server responded with an error."
PROTOCOL_VERSION = 24
SERVER_RESPONSES = {
    "1600": "Succeeded registration",
    "1601": "Failed registration",
    "1603": "Symmetric key sent",
    "1604": "Symmetric key accepted",
    "1605": "Message received",
    "1609": "General error"
}


def get_message_server(write=False):
    """
    :return: the message server.
    """
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
            msg_srv["key"] = b64decode(message_server[3].strip())
            return msg_srv
    except Exception as e:
        print(str(e))
        print("Can't open message server details")
        return default_msg_server()


def get_version():
    """
    :return: the protocol version.
    """
    return PROTOCOL_VERSION


def load_clients():
    """
    Loads clients from file
    :return: a list of give clients
    """
    try:
        with open(CLIENT_FILE, 'r') as clients_file:
            clients_list = clients_file.readlines()
            if clients_list is None or not clients_list:
                raise LookupError
            clients = []
            for row in clients_list:
                # example - parsing this:
                """
                clientID: 219612343443330567787200566001537885281 Name: alice PasswordHash: 8a5eba0ab714cbcd4f314334f073c446c3092192de2e40271203a722f41648a5 LastSeen: 2024-01-28 22:34:33
                """
                client = row.split(" ")
                clients.append({
                    "clientID": client[1],
                    "name": client[3],
                    "passwordHash": client[5],
                    "lastSeen": client[7] + " " + client[8].strip()
                })
            return clients
    except Exception:
        return []


def default_msg_server():
    """
    :return: the default message server.
    """
    return {
        "ip": "127.0.0.1",
        "port": 1235,
        "name": "Printer 20",
        "uuid": "64f3f63985f04beb81a0e43321880182",
        "key": "MIGdMA0GCSqGSIb3DQEBA"
    }


def create_password_sha(password: str):
    """
    creates a sha256 from a given password.
    :param password: string representing a password.
    :return: a sha256 of the password.
    """
    sh = SHA256.new()
    sh.update(bytes(password, encoding='utf-8'))
    return sh.hexdigest()


def encrypt_aes_ng(key, data):
    """
    receives a key nonce and data and returns a tuple of iv, nonce and data encrypted.
    :param key: key used for encryption.
    :param data: dict of data to encrypt.
    :return: encrypted_data as dict.
    """
    cipher = AES.new(key, AES.MODE_CBC)
    iv = b64encode(cipher.iv).decode('utf-8')

    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    ct = b64encode(ct_bytes).decode('utf-8')
    return str(iv+ct), iv


def decrypt_ng(key, data, iv=None):
    """
    :param key: 
    :param data:
    :param iv:
    :return:
    """
    try:
        if iv is not None:
            parse_iv = b64decode(iv)
        else:
            parse_iv=b64decode(data[:24])
        parse_data = b64decode(data[24:])
        cipher = AES.new(key, AES.MODE_CBC, parse_iv)
        pt = unpad(cipher.decrypt(parse_data), AES.block_size)
        return pt
    except (ValueError, KeyError) as e:
        print("Got Error, Incorrect decryption")
        return e


def create_random_byte_key():
    """
    :return: random 16 bytes value as session key.
    """
    return get_random_bytes(16)


def create_nonce():
    """
    :return: random 8 bytes value as nonce.
    """
    return get_random_bytes(8)


def get_port():
    """
    :return: the auth server port number.
    """
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
