from datetime import datetime

from kerberos_auth_server import KerberosAuthServer as authserver
from kerberos_message_server import KerberosMessageServer as msgserver
from shared_server import *

CLIENT_FILE = "me.info"
ERROR_MESSAGE = "Server responded with an error."
SERVER_ID = "hmd7dkd8r7dje711"

class KerberosClient:
    """    
    This class represents a client used by the kerberos protocol.
    """
    def __init__(self):
        self._version = 24
        self._aes_key = None # a symetric key between client and message server
        self._ticket = None 
        self._sha256 = None # a symetric key between client and auth server


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
        """
        try:
            with open(CLIENT_FILE, 'r') as client_file:
                data = client_file.readlines()
                return {"username": data[0], "uuid": data[1]}
        except Exception as e:
            return e


    def create_authenticator(self, uuid):
        """
        creates an authenticator for message server using an AES symetric key.
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


    def register(self):
        """
        sends a register request to the auth server.
        when the client's info ('me.info') doesn't exist, fetch it as input.
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
            try:
                response = authserver.register(request)
                if response["code"] == 1601: # registration failed code
                    print(response["payload"])
                    exit(1)
                uuid = response["payload"]
            except ValueError as e:
                print(e)
                exit(1)
            self.sha256 = create_password_sha(password)
            with open(CLIENT_FILE, 'w') as client_file:
                client_file.writelines([username, uuid])
            
            print("Client registered successfully.")
            print(f"Client info: {self.get_client_info()}")
        except Exception as e:
            print(e)
            print("Unsuccessful registration.")
            exit(1)


    def receive_aes_key(self):
        """
        receives a symetric key between client and message server,
        and a ticket for the message server.
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
            try:
                response = authserver.generate_session_key(request)
                encrypted_key = response["aes_key"]
                ticket = response["ticket"]
            except ValueError as e:
                print(e)
                exit(1)
            decrypted_key = str(decrypt_aes(encrypted_key, self.sha256))
            self.aes_key = decrypted_key
            self.ticket = ticket
        except Exception as e:
            print(e)
            exit(1)
            

    def send_aes_key(self):
        """
        sends an authenticator and a ticket to the message server.
        """
        try:
            uuid = self.get_client_info()["uuid"]
            authenticator, authenticatorSize = self.create_authenticator(uuid)
            request = {
                "header": {
                    "clientID": uuid,
                    "version": self.version,
                    "code": 1028,
                    "payloadSize": authenticatorSize + len(self.ticket)
                },
                "payload":{
                    "authenticator": authenticator,
                    "ticket": self.ticket
                }
            }
            response = msgserver.get_and_decrypt_key(request)
            if response == 1609: # error code
                print(ERROR_MESSAGE)
                exit(1)
        except Exception as e:
            print(e)
            exit(1)


    def send_message(self):
        """
        encrypts the input message and sends it to the message server.
        """
        message = input("Type a message for the server: ")
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
            try:
                msgserver.receive_client_request(request)
            except ValueError as e:
                print(ERROR_MESSAGE)
                exit(1)
            print("Message sent.")
        except Exception as e:
            print(e)
            exit(1)


def main():
    client = KerberosClient()
    print(f"I'm a client!")
    print(f"my version is {client.version}")
    client.register()
    client.receive_aes_key()
    client.send_aes_key()
    while True:
        client.send_message()


if __name__ == "__main__":
    main()