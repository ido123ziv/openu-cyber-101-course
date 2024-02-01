from kerberos_auth_server import KerberosAuthServer as authserver
from shared_server import *
from Crypto.Random import get_random_bytes

CLIENT_FILE = "me.info"
ERROR_MESSAGE = "Server responded with an error."
# TODO use multiple message servers for now leave it
SERVER_ID = "hmd7dkd8r7dje711hmd7dkd8r7dje711hmd7dkd8r7dje711hmd7dkd8r7dje711"

class KerberosClient:
    """    
    This class represents a client used by the kerberos protocol.
    """
    def __init__(self):
        self.aes_key = None
        self.ticket = None
        self.sha256 = None


    def register(self, username: str):
        """
        sends a register request to the auth server.
        :param username: string representing a username.
        """
        try:
            with open(CLIENT_FILE, 'r') as client_file:
                data = client_file.readlines()
                username = data[0]
                uuid = data[1]
        except FileNotFoundError:
            username = input("Enter username: ")
            password = input("Enter password: ")
            request = {
                "username": username,
                "password": password
            }
            uuid = authserver.register_client(request)

        self.sha256 = create_password_sha(password)
        with open(CLIENT_FILE, 'w') as client_file:
            client_file.writelines([username, uuid])


    def receive_aes_key(self):
        """
        receives an aes key and a ticket to a message server.
        decrypts the key and saves it along with the ticket for future use.
        """
        nonce = create_nonce()
        encrypted_key, ticket = authserver.generate_session_key(self.uuid, SERVER_ID, nonce)
        try:
            decrypted_key = decrypt_aes(encrypted_key, self.sha256)
            self.aes_key = decrypted_key
            self.ticket = ticket
        except ValueError as e:
            print(e)
            print(ERROR_MESSAGE)
            

    def send_aes_key(self, aes_key):
        """
        sends an authenticator and a ticket to the message server.
        :param aes_key: AES Symmetric Key.
        """
        pass


    def send_message(self, message: str):
        """
        encrypts a given message and sends it to the message server.
        :param message: a message to encrypt.
        """
        nonce = create_nonce()
        encrypted_message = encrypt_aes(self.aes_key, nonce, message)
        request = {
            "message_size": len(encrypted_message),
            "message_IV": create_iv(),
            "message_content": encrypted_message
        }
        # TODO send reuest to message server