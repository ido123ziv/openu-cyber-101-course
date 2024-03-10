import sys
from datetime import datetime
import json
import struct
# import logging

from shared_server import *
import socket

CLIENT_FILE = "me.info"
SERVERS_FILE = "srv.info"
ERROR_MESSAGE = "Server responded with an error."
# TODO use multiple message servers for now leave it
SERVER_ID = "hmd7dkd8r7dje711hmd7dkd8r7dje711hmd7dkd8r7dje711hmd7dkd8r7dje711"


def read_servers_info():
    """
    reads from {} the servers information and stores to memory
    :return: a dict with both auth and messaging servers ip and port
    """.format(SERVERS_FILE)
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


def get_client_info():
    """
    :return: load current client from file
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
        This method uses the socket interface to interact with the servers, auth server and message server
        :param message: dict representing the request to server according to the accepted format.
        :param server: server kind -> default is auth. for message pass server="msg"
        :return: server's response
        """

        if server != "auth":
            server_ip = self._msg_server.get("ip")
            server_port = self._msg_server.get("port")
        else:
            server_ip = self._auth_server.get("ip")
            server_port = self._auth_server.get("port")
        try:

            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((server_ip, server_port))
        except socket.error as e:
            print("Socket error -> " + str(e))
            exit(1)
        try:
            header_data = struct.pack('<16sBH I',  str.encode(message["header"]["clientID"]), message["header"]["version"], message["header"]["code"], message["header"]["payloadSize"])

            client.send(header_data + message["payload"].encode("utf-8"))
            response = client.recv(1024)
            response = response.decode("utf-8")
            # print(f"Received: {response}")
            if not response or response is None:
                raise ValueError("Server response is empty")
            return response
        except KeyError as e:
            print(f"Wrong input of key - {e}")
            return {}
        except Exception as e:
            print(f"Error: {e}")
            return e
        finally:
            client.close()
            # print("Connection to server closed")

    @property
    def client_id(self):
        """
        :return: client id in system
        """
        return self._client_id

    def __client_id__(self, uuid):
        """
        :param uuid: server's response new uuid
        :return: saves uuid to system
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
        :param password: client password
        :return: saves sha of password
        """

        self._sha256 = str(create_password_sha(password)).encode()[32:]

    def register(self):
        """
        sends a register request to the auth server.
        """
        print("Register")
        try:
            client_info = get_client_info()
            if isinstance(client_info, Exception):  # Checks if an error occurred while getting client info
                raise client_info  # Raises the caught exception to handle it in the except block
            username = client_info["username"]
            uuid = client_info["uuid"]
            self.__client_id__(uuid)
            if self.sha256 is None:
                print(f"Welcome back user: {username}, uuid: {uuid}")
                password = input("Please retype your password: ")
                self.validate_existing_user(uuid, username, password)
        except (FileNotFoundError, IndexError) as e:
            print(f"Unable to find client information or invalid format in '{CLIENT_FILE}': {e}")
            # Prompting for user input if there is an issue with the client file
            username = input("Enter username: ")
            password = input("Enter password: ")
            self.attempt_registration(username, password)
        except Exception as e:
            print(f"Caught Exception: {str(e)}")
        else:
            print(f"Successfully registered with uuid: {self.client_id}")

    def validate_existing_user(self, client_id: str, username: str, password: str):
        """
        Validates if existing user is legit by comparing password sha using auth server
        :param client_id: stored client id
        :param username: stored username
        :param password: new input password
        :return: saves new sha or execption
        """
        print("existing user registering")

        payload = {
            "name": username,
            "password": password
        }
        request = {
            "header": {
                "clientID": client_id,
                "version": self.version,
                "code": 1024,
                "payloadSize": len(json.dumps(payload))
            },
            "payload": json.dumps(payload)
        }
        try:
            response = self.send_message_to_server(request)
            if isinstance(response, Exception):
                raise response
            response_data = json.loads(response)
            if "error" in response_data["payload"].lower() or response_data["code"] == 1601:
                raise ValueError("Server error: " + response_data["payload"])
            self.create_sha256(password)
        except json.JSONDecodeError:
            print("Not valid server response")
        except ValueError as e:
            print("Caught Value Error when validating password: " + str(e))
        except Exception as e:
            print(f"Unexpected registration error! " + str(e))

    def attempt_registration(self, username: str, password: str):
        """
        Attempts to register the client with the server and handle the response.
        :param username: new username
        :param password:
        :return:
        """
        print("new user registration")
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
        try:
            response = self.send_message_to_server(request)
            if isinstance(response, Exception):
                raise response
            response_data = json.loads(response)
            if "error" in response_data["payload"].lower():
                raise ValueError("Server error: " + response_data["payload"])
            if len(response_data["payload"]) < 16:
                raise ValueError("Server error, invalid client id")
            self.create_sha256(password)
            self.__client_id__(response_data["payload"])
            with open(CLIENT_FILE, 'w') as client_file:
                client_file.writelines([username + "\n", self.client_id])
            print("Registration attempt succeeded.")
        except json.JSONDecodeError:
            print("Not valid server response")
        except ValueError as e:
            print("Caught Value Error when registering to server: " + str(e))
        except Exception as e:
            print(f"registration error! " + str(e))

    def receive_aes_key(self):
        """
        receives an aes key and a ticket to a message server.
        decrypts the key and saves it along with the ticket for future use.
        """
        # print("Requesting AES KEY from Auth Server")
        try:
            # nonce = create_nonce()
            nonce = str(create_nonce())
            payload = {
                "serverID": SERVER_ID,
                "nonce": nonce
            }
            request = {
                "header": {
                    "clientID": self.client_id,
                    "version": self.version,
                    "code": 1027,
                },
                "payload": json.dumps(payload)
            }
            request["header"]["payloadSize"] = len(json.dumps(payload))
            response = self.send_message_to_server(request)
            response_data = json.loads(response)["payload"]
            encrypted_key = response_data["encrypted_key"]
            ticket = response_data["ticket"]
            try:
                decrypted_key = decrypt_ng(self.sha256, encrypted_key["aes_key"], encrypted_key["encrypted_key_iv"])
                if isinstance(decrypted_key, Exception):  # Checks if an error occurred while getting client info
                    raise decrypted_key
                self._aes_key = decrypted_key
                self._ticket = ticket
            except ValueError as e:
                print("Value Error: " + str(e))
                print(ERROR_MESSAGE)
        except json.JSONDecodeError as e:
            print("Response from server is not valid \n" + ERROR_MESSAGE)
        except Exception as e:
            print("Caught Error: " + str(e))

    def send_aes_key(self, server=SERVER_ID):
        """
        sends an authenticator and a ticket to the message server.
        :param server: messaging server id
        """
        # print(f"Sending AES KEY to: {server}")
        try:
            authenticator = self.create_authenticator(server, self.client_id)
            ticket = self.ticket
            payload = {
                "authenticator": authenticator,
                "ticket": ticket
            }
            request = {
                "header": {
                    "clientID": self.client_id,
                    "version": self.version,
                    "code": 1028,
                    "payloadSize": len(json.dumps(payload))
                },
                "payload": json.dumps(payload)
            }
            self.send_message_to_server(request, server="msg")
        except Exception as e:
            print("send_aes_key: {}".format(str(e)))

    def send_message_for_print(self, message: str):
        """
        encrypts a given message and sends it to the message server.
        :param message: a message to encrypt.
        """
        encrypted_message = encrypt_ng(self._aes_key, dict(encrypted_data=message.encode()))
        payload = {
            "messageSize": len(encrypted_message["encrypted_data"]),
            "messageIV": encrypted_message["iv"],
            "messageContent": encrypted_message["encrypted_data"]
        }
        request = {
            "header": {
                "clientID": self.client_id,
                "version": self.version,
                "code": 1029,
                "payloadSize": len(json.dumps(payload))
            },
            "payload": json.dumps(payload)
        }
        try:
            # print(f"Sending: {json.dumps(request)}")
            response = self.send_message_to_server(request, server="msg")
            # print(response)
        except Exception as e:
            print(f"Error: {str(e)}")
            print(ERROR_MESSAGE)

    def create_authenticator(self, server_id, client_id):

        """
        creates an authenticator using an AES key.
        :param client_id: client unique id.
        :param server_id: server unique id.
        :return: the authenticator that was created.
        """
        nonce = create_nonce()
        creation_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        unencrypted_data = {
            "version": str(self.version).encode(),
            "client_id": client_id.encode(),
            "server_id": server_id.encode(),
            "timestamp": creation_time.encode(),
            "nonce": nonce
        }
        encrypted_data = encrypt_ng(self._aes_key, unencrypted_data)

        return {
            "authenticatorIV": encrypted_data["iv"],
            "version": encrypted_data["version"],
            "clientID": encrypted_data["client_id"],
            "serverID": encrypted_data["server_id"],
            "creationTime": encrypted_data["timestamp"]
        }


def main():
    """
    Main function for creation of a client
    :return:
    """
    # logging.basicConfig(stream=sys.stdout, level=get_log_level())
    client = KerberosClient()

    client.register()
    client.receive_aes_key()
    client.send_aes_key()
    client.send_message_for_print("Message!")
    try:
        while True:
            message = input("What to send to server? ")
            client.send_message_for_print(message)
    except KeyboardInterrupt as e:
        print("Thanks for playing")


# Todo: support for multiple clients
if __name__ == "__main__":
    # print("Hello World")
    main()

