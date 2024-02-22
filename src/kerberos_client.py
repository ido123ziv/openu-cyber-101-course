from datetime import datetime

from kerberos_auth_server import KerberosAuthServer as authserver
from kerberos_message_server import KerberosMessageServer as msgserver
from shared_server import *

CLIENT_FILE = "me.info"
ERROR_MESSAGE = "Server responded with an error."
# TODO use multiple message servers for now leave it
SERVER_ID = "hmd7dkd8r7dje711hmd7dkd8r7dje711hmd7dkd8r7dje711hmd7dkd8r7dje711"

class KerberosClient:
    """    
    This class represents a client used by the kerberos protocol.
    """
    def __init__(self):
        self._version = 24
        self._aes_key = None
        self._ticket = None
        self._sha256 = None


    @property
    def version(self):
        """
        getter for version property 
        :return: the client's version
        """
        return self._version
    

    @property
    def aes_key(self):
        """
        getter for aes_key property 
        :return: the aes key
        """
        return self._aes_key
    

    @property
    def ticket(self):
        """
        getter for ticket property 
        :return: the ticket for the message server
        """
        return self._ticket
    

    @property
    def sha256(self):
        """
        getter for sha256 property 
        :return: the passwordHash
        """
        return self._sha256


    def get_client_info(self):
        """
        reads client's name and uuid from 'me.info' file.
        :return: a dict containing the name and the uuid. 
        raises FileNotFoundError if the file does not exist.
        """
        try:
            with open(CLIENT_FILE, 'r') as client_file:
                data = client_file.readlines()
                return {"username": data[0], "uuid": data[1]}
        except FileNotFoundError as e:
            return e


    def create_authenticator(self, uuid):
        """
        creates an authenticator using an AES key.
        :param uuid: client unique id.
        :return: the authenticator that was created.
        """
        nonce = create_nonce()
        encrypted_version = str(encrypt_aes(self.aes_key, nonce, get_version()))
        encrypted_client_id = str(encrypt_aes(self.aes_key, nonce, uuid))
        encrypted_server_id = str(encrypt_aes(self.aes_key, nonce, SERVER_ID))
        creation_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        encrypted_timestamp = str(encrypt_aes(self.aes_key, nonce, creation_time))
        iv = create_iv()

        authenticatorSize = len(iv) + len(encrypted_version) + len(encrypted_client_id) + len(encrypted_server_id) + len(encrypted_timestamp)
        return {
            "authenticatorIV": iv,
            "version": encrypted_version,
            "clientID": encrypted_client_id,
            "serverID": encrypted_server_id,
            "creationTime": encrypted_timestamp
        }, authenticatorSize


    def register(self, username: str):
        """
        sends a register request to the auth server.
        :param username: string representing a username.
        """
        try:
            client_info = self.get_client_info()
            username = client_info["username"]
            uuid = client_info["uuid"]
        except FileNotFoundError as e:
            print(e)
            username = input("Enter username: ")
            password = input("Enter password: ")
            request = {
                "header":{

                    "clientID": "clientID", # the server will ignore this field
                    "version": self.version,
                    "code": 1024,
                    "payloadSize": len(username) + len(password)
                },
                "payload":{
                    "name": username,
                    "password": password
                }
            }
            uuid = authserver.register(request)["Payload"]
            self.sha256 = create_password_sha(password)
        finally:
            with open(CLIENT_FILE, 'w') as client_file:
                client_file.writelines([username, uuid])


    def receive_aes_key(self):
        """
        receives an aes key and a ticket to a message server.
        decrypts the key and saves it along with the ticket for future use.
        """
        try:
            client_info = self.get_client_info()
            uuid = client_info["uuid"]
            nonce = create_nonce()
            request = {
                "header":{
                    "clientID": uuid,
                    "version": self.version,
                    "code": 1027,
                    "payloadSize": len(SERVER_ID) + len(nonce)
                },
                "payload":{
                    "serverID": SERVER_ID,
                    "nonce": nonce
                }
            }
            encrypted_key, ticket = authserver.generate_session_key(request)
            try:
                decrypted_key = str(decrypt_aes(encrypted_key, self.sha256))
                self.aes_key = decrypted_key
                self.ticket = ticket
            except ValueError as e:
                print(e)
                print(ERROR_MESSAGE)
        except FileNotFoundError:
            print("File 'me.info' was not found.")
            exit(1)
            

    def send_aes_key(self, aes_key):
        """
        sends an authenticator and a ticket to the message server.
        :param aes_key: AES Symmetric Key.
        """
        try:
            uuid = self.get_client_info()["uuid"]
            authenticator, authenticatorSize = self.create_authenticator(uuid)
            ticket = self.ticket
            request = {
                "header": {
                    "clientID": uuid,
                    "version": self.version,
                    "code": 1028,
                    "payloadSize": authenticatorSize + len(ticket)
                },
                "payload":{
                    "authenticator": authenticator,
                    "ticket": ticket
                }
            }
            msgserver.receive_aes_key(request)
        except FileNotFoundError:
            print("File 'me.info' was not found.")
            exit(1)


    def send_message(self, message: str):
        """
        encrypts a given message and sends it to the message server.
        :param message: a message to encrypt.
        """
        try:
            client_info = self.get_client_info()
            uuid = client_info["uuid"]
            nonce = create_nonce()
            encrypted_message = str(encrypt_aes(self.aes_key, nonce, message))
            encrypted_message_len = len(encrypted_message)
            iv = create_iv()
            request = {
                "header": {
                    "clientID": uuid,
                    "version": self.version,
                    "code": 1029,
                    "payloadSize": len(encrypted_message_len) + len(iv) + encrypted_message_len
                },
                "payload":{
                    "messageSize": encrypted_message_len,
                    "messageIV": iv,
                    "messageContent": encrypted_message
                }
            }
            msgserver.receive_client_request(request)
        except FileNotFoundError:
            print("File 'me.info' was not found.")
            exit(1)
