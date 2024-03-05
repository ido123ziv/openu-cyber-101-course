import json
import struct

# from kerberos_auth_server import KerberosAuthServer as authserver
from shared_server import *
import socket

CLIENT_FILE = "me.info"
SERVERS_FILE = "srv.info"
ERROR_MESSAGE = "Server responded with an error."
# TODO use multiple message servers for now leave it
SERVER_ID = "hmd7dkd8r7dje711hmd7dkd8r7dje711hmd7dkd8r7dje711hmd7dkd8r7dje711"


def read_servers_info():
    """

    :return:
    """
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
        self._client_id = None
        self._aes_key = None
        self._ticket = None
        self._sha256 = None

    def send_message_to_server(self, message: dict, server="auth"):
        """

        :param message:
        :param server:
        :return:
        """

        if server != "auth":
            server_ip = self._msg_server.get("ip")
            server_port = self._msg_server.get("port")
        else:
            server_ip = self._auth_server.get("ip")
            server_port = self._auth_server.get("port")

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # TODO: better error handeling. If socket can't be open say it
        client.connect((server_ip, server_port))
        try:
            header_data = struct.pack('<16sBH I',  str.encode(message["header"]["clientID"]), message["header"]["version"], message["header"]["code"], message["header"]["payloadSize"])

            client.send(header_data + message["payload"].encode("utf-8"))
            response = client.recv(1024)
            response = response.decode("utf-8")
            print(f"Received: {response}")
            return response
        except KeyError as e:
            print(f"Wrong input of key - {e}")
        except Exception as e:
            print(f"Error: {e}")
        finally:
            client.close()
            print("Connection to server closed")

    @property
    def client_id(self):
        """

        :return:
        """
        return self._client_id

    def __client_id__(self, uuid):
        """

        :param uuid:
        :return:
        """
        self._client_id = uuid

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
        """

        :param password:
        :return:
        """
        self._sha256 = create_password_sha(password)

    def get_client_info(self):
        """

        :return:
        """
        try:
            with open(CLIENT_FILE, 'r') as client_file:
                data = client_file.readlines()
                return {"username": data[0].strip(), "uuid": data[1].strip()}
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
            self.__client_id__(uuid)
        except Exception as e:
            print(f"Caught Exception: {str(e)}")
            username = input("Enter username: ")
            password = input("Enter password: ")
            payload = {
                    "name": username,
                    "password": password
                }
            request = {
                "header": {
                    "clientID": "client_id12345678",  # the server will ignore this field
                    "version": self.version,
                    "code": 1024,
                    "payloadSize": len(json.dumps(payload))
                },
                "payload": json.dumps(payload)
            }
            response = self.send_message_to_server(request)
            uuid = json.loads(response)["payload"]
            # uuid = authserver.register(request)["payload"]
            self.create_sha256(password)
            self.__client_id__(uuid)
            # TODO: better error handling on this, finally gets a lot of errors in this flow
        finally:
            # TODO: fix UnboundLocalError: local variable 'uuid' referenced before assignment
            if username and uuid:
                with open(CLIENT_FILE, 'w') as client_file:
                    client_file.writelines([username + "\n", uuid])

    def receive_aes_key(self):
        """
        receives an aes key and a ticket to a message server.
        decrypts the key and saves it along with the ticket for future use.
        """
        nonce = create_nonce()
        # encrypted_key, ticket = authserver.generate_session_key(self.uuid, SERVER_ID, nonce)
        try:
            # decrypted_key = decrypt_aes(encrypted_key, self.sha256)
            # self.aes_key = decrypted_key
            # self.ticket = ticket
            pass
        except ValueError as e:
            print(f"Error: {str(e)}")
            print(ERROR_MESSAGE)

    def send_aes_key(self, aes_key):
        """
        sends an authenticator and a ticket to the message server.
        :param aes_key: AES Symmetric Key.
        """
        pass

    def send_message_for_print(self, message: str):
        """
        encrypts a given message and sends it to the message server.
        :param message: a message to encrypt.
        """
        nonce = create_nonce()
        # encrypted_message = encrypt_aes(self.aes_key, nonce, message)
        encrypted_message = message.strip()
        payload = {
            "messageSize": len(encrypted_message),
            # "messageIV": create_iv(),
            "messageIV": str(create_iv()),
            "messageContent": encrypted_message
        }
        request = {
            "header": {
                "clientID": "client_id12345678",  # the server will ignore this field
                "version": self.version,
                "code": 1029,
                "payloadSize": len(json.dumps(payload))
            },
            "payload": json.dumps(payload)
        }
        try:
            print(f"Sending: {json.dumps(request)}")
            response = self.send_message_to_server(request, server="msg")
            print(response)
        except Exception as e:
            print(f"Error: {str(e)}")
            print(ERROR_MESSAGE)


def main():
    """

    :return:
    """
    client = KerberosClient()
    client.register()
    client.send_message_for_print("Message!")


# Todo: support for multiple clients
if __name__ == "__main__":
    print("Hello World")
    main()
