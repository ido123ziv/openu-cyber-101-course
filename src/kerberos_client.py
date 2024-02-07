import json

from kerberos_auth_server import KerberosAuthServer as authserver
from shared_server import *
import socket

CLIENT_FILE = "me.info"
SERVERS_FILE = "srv.info"
ERROR_MESSAGE = "Server responded with an error."
# TODO use multiple message servers for now leave it
SERVER_ID = "hmd7dkd8r7dje711hmd7dkd8r7dje711hmd7dkd8r7dje711hmd7dkd8r7dje711"


def read_servers_info():
    try:
        with open(SERVERS_FILE, 'r') as servers_file:
            servers_details = servers_file.readlines()
            # TODO: add checks for validation
            auth_details = servers_details[0].split(':')
            msg_details = servers_details[1].split(':')
            return {
                "auth": {
                    "ip": auth_details[0],
                    "port": int(auth_details[1].strip())
                },
                "msg": {
                    "ip": msg_details[0],
                    "port": int(msg_details[1].strip())
                }
            }
    except Exception as e:
        print(str(e))
        exit(1)


class KerberosClient:
    """    
    This class represents a client used by the kerberos protocol.
    """
    def __init__(self):
        servers = read_servers_info()
        self._auth_server = servers.get("auth")
        self._msg_server = servers.get("msg")
        self._version = get_version()
        self._aes_key = None
        self._ticket = None
        self._sha256 = None

    def send_message(self, message: str, server="auth"):

        if server != "auth":
            server_ip = self._msg_server.get("ip")
            server_port = self._msg_server.get("port")
        else:
            server_ip = self._auth_server.get("ip")
            server_port = self._auth_server.get("port")

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((server_ip, server_port))
        try:
            client.send(message.encode("utf-8")[:1024])
            response = client.recv(1024)
            response = response.decode("utf-8")
            print(f"Received: {response}")
            return response
        except Exception as e:
            print(f"Error: {e}")
        finally:
            client.close()
            print("Connection to server closed")

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

    def create_sha256(self, password):
        self._sha256 = create_password_sha(password)

    def get_client_info(self):
        try:
            with open(CLIENT_FILE, 'r') as client_file:
                data = client_file.readlines()
                return {"username": data[0], "uuid": data[1]}
        except FileNotFoundError as e:
            print(str(e))
            return e
        except IndexError as e:
            print(str(e))
            return e

    def register(self):
        """
        sends a register request to the auth server.
        :param username: string representing a username.
        """
        try:
            # TODO: check if e is an error
            client_info = self.get_client_info()
            username = client_info["username"]
            uuid = client_info["uuid"]
        except Exception as e:
            print(e)
            username = input("Enter username: ")
            password = input("Enter password: ")
            request = {
                "header": {
                    "clientID": "clientID",  # the server will ignore this field
                    "version": self.version,
                    "code": 1024,
                    "payloadSize": len(username) + len(password)
                },
                "payload": {
                    "name": username,
                    "password": password
                }
            }
            response = self.send_message(json.dumps(request))
            uuid = json.loads(response)["payload"]
            # uuid = authserver.register(request)["payload"]
            self.create_sha256(password)
            # TODO: better error handling on this, finally gets a lot of errors in this flow
        finally:
            if username and uuid:
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


    # def send_message(self, message: str):
    #     """
    #     encrypts a given message and sends it to the message server.
    #     :param message: a message to encrypt.
    #     """
    #     nonce = create_nonce()
    #     encrypted_message = encrypt_aes(self.aes_key, nonce, message)
    #     request = {
    #         "message_size": len(encrypted_message),
    #         "message_IV": create_iv(),
    #         "message_content": encrypted_message
    #     }
    #     # TODO send reuest to message server


def main():
    client = KerberosClient()
    client.register()


if __name__ == "__main__":
    print("Hello World")
    main()
