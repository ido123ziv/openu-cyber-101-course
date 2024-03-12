import json
import struct
from datetime import datetime
import threading
import socket

from shared_server import *

SERVER_FILE = "msg.info"


def default_error():
    """
    :return: default error code
    """
    print("server responded with an error")
    return 1609


def message_keys(key: int):
    """
    helper to get info from message server, no need when using single server
    :param key: int -> key in dict
    :return: string name of the key
    """
    switcher = {
        0: "port",
        1: "name",
        2: "uuid",
        3: "key"
    }
    return switcher.get(key, -1)


class KerberosMessageServer:
    """
    This class represents a kerberos message server.
    """

    def __init__(self):
        try:
            server = get_message_server()
            self._port = int(server["port"])
            self._ip = server["ip"]
            self._name = server["name"]
            self._uuid = server["uuid"]
            self._version = get_version()
            self._key = server["key"]
            self._lock = threading.Lock()
            self._clients = {}
        except Exception as e:
            print("Init error: " + str(e))
            default_error()


    @property
    def ip(self):
        return self._ip


    @property
    def version(self):
        return self._version


    @property
    def port(self):
        """
        getter for port property
        :return: the object's port
        """
        return self._port


    @property
    def name(self):
        """
        getter for name property
        :return: the object's name
        """
        return self._name


    @property
    def uuid(self):
        """
        getter for uuid property
        :return: the object's uuid
        """
        return self._uuid


    @property
    def key(self):
        """
        getter for key property
        :return: the object's key
        """
        return self._key


    @property
    def lock(self):
        """
        getter for lock property
        :return: the object's lock
        """
        return self._lock


    def get_and_decrypt_key(self, request):
        """
        Message Server function that gets a request from client and registers its key
        :param request: a dict with ticket and Authenticator
        :return: response code whether succeeded or not
        """
        try:
            ticket = request.get("ticket")
            authenticator = request.get("authenticator")
            aes_key = decrypt_ng(self.key, ticket["aes_key"], ticket["ticket_iv"])
            ticket_expiration_time = decrypt_ng(self.key, ticket["expiration_time"]).decode("utf-8")
            ticket_expiration_timef = datetime.strptime(ticket_expiration_time,'%Y-%m-%d %H:%M:%S')
            client_id = ticket.get("client_id")
            # TODO compare client id if ticket to authenticator
            decrypted_authenticator={}
            for k,v in authenticator.items():
                # print(k)
                if "iv" not in k.lower():
                    decrypted_value = decrypt_ng(aes_key, v).decode("utf-8")
                    decrypted_authenticator[k] = decrypted_value
                # else:
                #     print(v)
            if not client_id == decrypted_authenticator["clientID"]:
                raise ValueError("client id don't match")
                
            if datetime.strptime(decrypted_authenticator["creationTime"],'%Y-%m-%d %H:%M:%S') > ticket_expiration_timef:
                raise ValueError("expired ticket")
            
            if not decrypted_authenticator["version"] == str(self.version):
                raise ValueError("incompatible version")

            if not decrypted_authenticator["serverID"] == self.uuid:
                raise ValueError("Wrong Message Server")

            # recieved_client_id = decrypt_ng(aes_key, authenticator["clientID"], authenticator["authenticatorIV"])

            self._clients[client_id] = {
                "key": aes_key,
                "expire_timestamp": ticket_expiration_time
            }
            print("Symmetric key accepted")
            return dict(Code=1604)
        except Exception as e:
            print("get_and_decrypt_key error: " + str(e))
            return default_error()


    def print_message(self, client_id, request):
        """
        Prints a user message
        :param client_id:
        :param request: a dict with message details
        :return: success code
        """
        try:
            if len(request["messageContent"]) != request["messageSize"]:
                raise ValueError("Invalid Message, doesn't match size")
            # TODO: check if message size matches the payload
            message = request["messageContent"]
            if client_id not in self._clients.keys():
                raise ValueError("Unregistered User")
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            if now > self._clients[client_id]["expire_timestamp"]:
                raise ValueError("Expired Ticket")
            client_key = self._clients[client_id]["key"]
            decrypted_message = decrypt_ng(client_key, message).decode("utf-8")
            print("decrypted message: " + decrypted_message)
            return dict(Code=1605)
        except Exception as e:
            print("print_message error: " + str(e))
            return default_error()


    def receive_client_request(self, client_socket, addr):
        try:
            header_data = client_socket.recv(23)
            if len(header_data) != 23:
                print("Header size didn't match constraints.")
                raise ValueError

            # Unpack the header fields using struct
            client_id, version, code, payload_size = struct.unpack('<16sBH I', header_data)
            payload_data = client_socket.recv(payload_size)
            if len(payload_data) != payload_size:
                print("Payload size didn't match payload, Aborting!.")
                raise ValueError

            request = {
                "header": {
                    "clientID": client_id.decode("utf-8"),
                    "version": version,
                    "code": code,
                    "payloadSize": payload_size
                },
                "payload": payload_data.decode("utf-8")
            }
            response = self.handle_client_request(request)
            client_socket.send(json.dumps(response).encode("utf-8"))
        except Exception as e:
            print(f"Error when handling client: {e}")
        finally:
            client_socket.close()


    def handle_client_request(self, request):
        """
        Handles servers request from clients by determinate error codes
        :param request: dict of object from user
        :return: success code
        """
        try:
            if not request:
                raise NameError("request is empty!")
            try:
                payload = json.loads(request["payload"])
            except Exception as e:
                raise ValueError("Payload is not valid JSON. \nPayload:{}\nError:{}".format(request["payload"], str(e)))
            code = request["header"]["code"]
            if code == 1028:
                return self.get_and_decrypt_key(payload)
            elif code == 1029:
                try:
                    payload = json.loads(request["payload"])
                    return self.print_message(request["header"]["clientID"], payload)
                except Exception as e:
                    raise ValueError(
                        "Payload is not valid JSON. \nPayload:{}\nError:{}".format(request["payload"], str(e)))
            else:
                raise ValueError("Not Valid request code")
        except KeyError as e:
            print("Invalid request. \nRequest: {}\nError: {}".format(request, str(e)))
        except Exception as e:
            print("handle_client_request error: " + str(e))
            return {"code": default_error()}


    def start_server(self):
        """
        infinite loop, listening to requests from clients
        :return:
        """
        # TODO: add methods to check this
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # bind the socket to the host and port
            server.bind((self.ip, self.port))
            # listen for incoming connections
            server.listen()
            print(f"Listening on {self.ip}:{self.port}")

            while True:
                # accept a client connection
                client_socket, addr = server.accept()
                # start a new thread to handle the client
                thread = threading.Thread(target=self.receive_client_request, args=(client_socket, addr,))
                thread.start()
        except Exception as e:
            print(f"Error: {e}")
        finally:
            client_socket.close()


def main():
    server = KerberosMessageServer()
    print("Kerberos Message Server")
    print(f"My name is {server.name}")
    print(f"My uuid is {server.uuid}")

    server.start_server()


if __name__ == "__main__":
    main()
