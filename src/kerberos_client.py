from datetime import datetime
import json
import struct

from shared_server import *
import socket

CLIENT_FILE = f"{FOLDER_NAME}/me.info"
SERVERS_FILE = f"{FOLDER_NAME}/srv.info"
ERROR_MESSAGE = "Server responded with an error."
SERVER_ID = "hmd7dkd8r7dje711"


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
        self._registration_count = 0
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
        try:
            if self._registration_count > 5:
                raise ValueError("Max attempts exceeded!")
            client_info = get_client_info()
            if isinstance(client_info, Exception):  # Checks if an error occurred while getting client info
                raise client_info  # Raises the caught exception to handle it in the except block
            username = client_info["username"]
            uuid = client_info["uuid"]
            self.__client_id__(uuid)
            self._registration_count += 1
            if self.sha256 is None:
                print(f"Welcome back user: {username}, uuid: {uuid}")
                password = input("Please retype your password: ")
                return self.validate_existing_user(uuid, username, password)

        except (FileNotFoundError, IndexError):
            # Prompting for user input if there is an issue with the client file
            username = input("Enter username: ")
            if len(username) > 255:
                return ValueError("Too long username.\nUnsuccessful registration.")
            password = input("Enter password: ")
            if len(password) > 255:
                return ValueError("Too long password.\nUnsuccessful registration.")
            self.attempt_registration(username, password)
            print(f"Successfully registered with uuid: {self.client_id}")
        except Exception as e:
            print(f"Caught Exception: {str(e)}")


    def validate_existing_user(self, client_id: str, username: str, password: str):
        """
        Validates if existing user is legit by comparing password sha using auth server
        :param client_id: stored client id
        :param username: stored username
        :param password: new input password
        """
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
                return ValueError("Server error: " + response_data["payload"])
            self.create_sha256(password)
            print("Successfull registration")
        except json.JSONDecodeError:
            print("Not valid server response")
        except ValueError as e:
            print("Caught Value Error when validating password: " + str(e))
            self.register()
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
        try:
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
            if response is None:
                raise ValueError("Empty Response from Server")
            if isinstance(response, ValueError):
                raise response
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
                exit(1)
        except json.JSONDecodeError as e:
            print("Response from server is not valid \n" + ERROR_MESSAGE)
        except Exception as e:
            print("Caught Error: " + str(e))
            exit(1)


    def send_aes_key(self, server=SERVER_ID):
        """
        sends an authenticator and a ticket to the message server.
        :param server: messaging server id
        """
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
            response = self.send_message_to_server(request, server="msg")
            if isinstance(response,Exception):
                raise response
        except KeyError as e:
            print("I fucked up: {}".format(str(e)))
        except Exception as e:
            print("send_aes_key: {}".format(str(e)))
            exit(1)


    def send_message_for_print(self, message: str):
        """
        encrypts a given message and sends it to the message server.
        :param message: a message to encrypt.
        """
        encrypted_message, message_iv = encrypt_aes_ng(self.aes_key, message.encode())
        payload = {
            "messageSize": len(encrypted_message),
            "messageIV": message_iv,
            "messageContent": encrypted_message
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
            response = self.send_message_to_server(request, server="msg")
            print("Server response: " + response)

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
        encrypted_data = {}
        for k,v in unencrypted_data.items():
            encrypted_data[k],client_iv=encrypt_aes_ng(self.aes_key,v)
            if "client" in k:
                encrypted_data["iv"] = client_iv

        return {
            "authenticatorIV": encrypted_data["iv"],
            "version": encrypted_data["version"],
            "clientID": encrypted_data["client_id"],
            "serverID": encrypted_data["server_id"],
            "creationTime": encrypted_data["timestamp"]
        }


def main():
    client = KerberosClient()
    # try:
    #     client.register()
    # except Exception:
    #     exit(1)
    response = client.register()
    while isinstance(response, Exception):
        print(response)
        response = client.register()
    client.receive_aes_key()
    client.send_aes_key()
    try:
        while True:
            message = input("What to send to server? ")
            client.send_message_for_print(message)
    except KeyboardInterrupt:
        print("\nThanks for playing!")


# Todo: support for multiple clients
if __name__ == "__main__":
    main()
