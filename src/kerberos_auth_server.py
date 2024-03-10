import json
import struct
from datetime import datetime, timedelta

import socket
import threading
from shared_server import *
from uuid import uuid1
import ast
CLIENT_FILE = "clients.info"
SERVERS_FILE = "servers.info"
SERVER_IP = "127.0.0.1"


def create_uuid():
    """creates uuid for each request, represent a client"""
    return uuid1().int


class KerberosAuthServer:
    """
    This class represents an auth server used by the kerberos protocol and handles all the commands
    """

    def __init__(self):
        """
        creates an object
        """
        self._clients = load_clients()
        self._port = get_port()
        self._server_ip = SERVER_IP
        self._version = get_version()
        self._message_server = get_message_servers()
        self._servers = {}
        # self.lock = threading.Lock()

    @property
    def server_ip(self):
        """
        :return: current server ip
        """
        return self._server_ip

    @property
    def clients(self):
        """
        getter for clients list
        :return: a list of clients
        """
        return self._clients

    def __client_ids__(self):
        """
        :return: a list with all client ids
        """
        return [x["clientID"] for x in self.clients]

    @property
    def port(self):
        """
        getter for port property 
        :return: the port number
        """
        return self._port

    @property
    def version(self):
        """
        getter for version property 
        :return: the server version
        """
        return self._version

    @property
    def servers(self):
        """
        getter for servers property 
        :return: a list of message servers
        """
        return self._servers

    @property
    def message_server(self):
        """
        getter for message_sever property 
        :return: dict of current message server info
        """
        return self._message_server

    def get_clients_names(self):
        """
        getting a list of names from current client list
        :return: a list of all client names
        """
        return [x["name"] for x in self.clients]

    def generate_session_key(self, request: dict):
        """
        :param request: client's request as a dict
        :return: a tuple of AES Key and ticket encrypted
        """
        try:
            clients_ids = self.__client_ids__()
            client_index = clients_ids.index(client_id)
            client = self.clients[client_index]
        except Exception as e:
            print("Client is not registered! " + str(e))
            raise ValueError("Client Not Registered")

        key = client.get("passwordHash")
        bytes_key = str(key).encode()[32:]
        print(f"bytes: {bytes_key}, len: {len(bytes_key)}")

        session_key = create_random_byte_key(16)
        client_key = encrypt_ng(bytes_key, session_key, nonce=nonce)

        creation_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        expiration_time = (datetime.now() + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')

        ticket_key = encrypt_ng(session_key, session_key, time=expiration_time.encode())

        ticket = self.generate_ticket(client_id, server_id,  creation_time)
        ticket["ticket_iv"] = ticket_key["iv"]
        ticket["aes_key"] = ticket_key["encrypted_data"]
        ticket["expiration_time"] = ticket_key["time"]


        return {
            "encrypted_key_iv": client_key["iv"],
            "nonce": client_key["nonce"],
            "aes_key": client_key["encrypted_data"],
            "ticket": ticket
        }

    def generate_ticket(self, client_id, server_id, creation_time):
        """
        generate tgt from given key
        :param creation_time:
        :param server_id: message server id
        :param client_id: client initiated request
        :return: tgt
        """
        return {
            # TODO: change to message server version
            "version": self.version,
            "client_id": client_id,
            "server_id": server_id,
            "creation_timestamp": creation_time
        }

    def register(self, request):
        """
        These methods handle the registration of a client to the server
        :return: if the register succeeded
        """
        try:
            if request["name"] in self.get_clients_names():
                password_hash = create_password_sha(request["password"])
                client_index = self.get_clients_names().index(request["name"])
                client = self.clients[client_index]
                if password_hash != client["passwordHash"]:
                    raise ValueError("Client Already Registered, password incorrect.")
                return {
                    "code": 1600,
                    "version": self.version,
                    "payloadSize": len(str(client["clientID"])),
                    "payload": client["clientID"]
                }
            else:
                client_id = str(create_uuid())[:16]
                password_hash = create_password_sha(request["password"])
                self.clients.append(
                    {
                        "clientID": client_id,
                        "name": request["name"],
                        "passwordHash": str(password_hash),
                        "lastSeen": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }
                )
                add_client_to_file(self.clients)
                return {
                    "code": 1600,
                    "version": self.version,
                    "payloadSize": len(str(client_id)),
                    "payload": client_id
                }

        except Exception as e:
            print("register error: \n" + str(e))
            error_response = "Error! can't register user because of {}".format(str(e))
            return {
                "code": 1601,
                "version": self.version,
                "payloadSize": len(error_response),
                "payload": error_response
            }

    def handle_key_request(self, request):
        """
        This function request a key for messaging server and generates a ticket, sending back to client
        :param request: client request
        :return: server response with key and ticket or Exception
        """
        received_payload = json.loads(request["payload"])
        client_id = request["header"]["clientID"]
        nonce = ast.literal_eval(received_payload["nonce"])
        response = self.generate_session_key(client_id,
                                             self.message_server.get("uuid"), nonce)
        print("Created session key!")
        print(f"generate_session_key: {response}")
        encrypted_key = {
            "aes_key": response.get('aes_key'),
            "nonce": response.get('nonce'),
            "encrypted_key_iv": response.get('encrypted_key_iv')
        }
        payload = {
            "encrypted_key": encrypted_key,
            "ticket": response.get('ticket')
        }
        print(f"payload: \n{payload}")
        return {
            "header": {
                "code": 1603,
                "version": self.version,
                "payloadSize": len(payload)
            },
            "payload": payload
        }

    def receive_client_request(self, client_socket, addr):
        """
        This method recieves the byte stream from socket, parses it and sends internally for handling
        :param client_socket: socket listing to
        :param addr: address listening to
        :return: None
        """
        try:
            # receive 23 bytes of header (client id - 16, version - 1, code -2, size - 4)
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
            print(f"Server will now respond with: {response}")
            client_socket.send(json.dumps(response, default=str).encode("utf-8"))
        except Exception as e:
            print(f"Error when handling client: {e}")
        finally:
            client_socket.close()
            print(f"Connection to client ({addr[0]}:{addr[1]}) closed")

    def handle_client_request(self, request):
        """
        handles the request from the client
        :param request: parsed dict of info
        :return: error code
        """
        try:

            if not request:
                raise NameError("request is empty!")
            if "error" in request["header"]["clientID"].lower():
                raise ValueError("Invalid ClientId")
            if request["header"]["version"] != self.version:
                raise ValueError("Server version don't match client version")
            print(f"handle_client_request: \n{request}")
            code = request["header"]["code"]
            try:
                payload = json.loads(request["payload"])
            except Exception as e:
                raise ValueError("Payload is not valid JSON. \nPayload:{}\nError:{}".format(request["payload"], str(e)))
            if code == 1024:
                return self.register(payload)
            if code == 1027:
                print("Client requested key")
                return self.handle_key_request(request)

            return "Not supported yet!"
        except KeyError as e:
            print(f"Got Key Error on {e}")
            exit(1)
        except Exception as e:
            print("handle_client_request error: \n" + str(e))
            exit(1)

    def start_server(self):
        """
        infinite loop of listening server
        :return:
        """
        try:
            print(f"Server Started on port {self.port}")
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # bind the socket to the host and port
            server.bind((self.server_ip, self.port))
            # listen for incoming connections
            server.listen()
            print(f"Listening on {self.server_ip}:{self.port}")

            while True:
                # accept a client connection
                client_socket, addr = server.accept()
                print(f"Accepted connection from {addr[0]}:{addr[1]}")
                # start a new thread to handle the client
                thread = threading.Thread(target=self.receive_client_request, args=(client_socket, addr,))
                thread.start()
        except Exception as e:
            print(f"Error: {e}")
        finally:
            server.close()


def load_clients():
    # TODO: make it better than addressing the locations hard coded
    """
    Loads client from file
    :return: a list of give clients
    """
    try:
        with open(CLIENT_FILE, 'r') as clients_file:
            clients_list = clients_file.readlines()
            if clients_list is None or not clients_list:
                raise LookupError
            clients = []
            for row in clients_list:
                """
                parsing this:
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
    except Exception as e:
        print("load_clients error: \n" + str(e))
        print("No clients found")
        return []


def add_client_to_file(clients):
    """
    writes client list to file
    :param clients: current client list
    """
    backup_client = load_clients()
    try:
        with open(CLIENT_FILE, 'w+') as clients_file:
            for client in clients:
                # clients_file.write(client + "\n")
                clients_file.write("clientID: " + client.get("clientID"))
                clients_file.write(" Name: " + client.get("name"))
                clients_file.write(" PasswordHash: " + client.get("passwordHash"))
                clients_file.write(" LastSeen: " + client.get("lastSeen") + "\n")
    except Exception as e:
        print("add_clients_to_file error: \n" + str(e))
        print("Couldn't add client, defaulting to previous state")
        with open(CLIENT_FILE, 'w') as clients_file:
            if backup_client is not None or backup_client != []:
                clients_file.writelines(backup_client)


def main():
    """
    main function
    """
    server = KerberosAuthServer()
    print(f"I'm a Kerberos Server!")
    print(f"my clients are: {server.clients}")
    print(f"using port: {server.port}")
    print(f"my version is {server.version}")
    print(f"message_sever in use: {server.message_server}")
    print(f"my messaging servers {server.servers}")
    server.start_server()


if __name__ == "__main__":
    print("Hello World")
    main()
