import json
import struct
from datetime import datetime, timedelta

import socket
# TODO: add struct usage
import threading
from shared_server import *
import base64
from Crypto.Cipher import AES
from uuid import uuid1
CLIENT_FILE = "clients.info"
# todo use multiple message services for now leave it
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

        :return:
        """
        return self._server_ip

    @property
    def clients(self):
        """
        getter for clients list
        :return: a list of clients
        """
        return self._clients

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

    # TODO add support for multi servers using threads
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

    # TODO add a parsing to the client names
    def get_clients_names(self):
        """
        getting a list of names from current client list
        :return: a list of all client names
        """
        return [x["name"] for x in self.clients]

    def generate_session_key(self, client_id, server_id, nonce):
        """
        :param nonce: random value created by the client
        :param server_id: messaging server id
        :param client_id: client id of user initiated the request
        :return: a tuple of AES Key and ticket encrypted
        """
        clients_ids = [x["clientID"] for x in self.clients]
        client_index = clients_ids.index(client_id)
        client = self.clients[client_index]
        key = client.get("passwordHash")
        bytes_key = str(key).encode()[32:]
        print(f"bytes: {bytes_key}, len: {len(bytes_key)}")
        aes_key = AES.new(bytes_key, AES.MODE_CBC, iv=create_iv())
        ticket_aes_key = AES.new(base64.b64decode(self.message_server.get('key')), AES.MODE_CBC, iv=create_iv())
        encrypted_ticket_key = encrypt_aes(ticket_aes_key, nonce, bytes_key)
        creation_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        expiration_time = (datetime.now() + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')
        encrypted_time = encrypt_aes(ticket_aes_key, nonce, expiration_time.encode())
        # aes_key = AES.new(get_random_bytes(32), AES.MODE_CBC, iv=get_random_bytes(16))
        ticket_payload = self.generate_ticket(client_id, server_id, encrypted_ticket_key, creation_time, encrypted_time)
        return {
            "key": aes_key,
            "ticket": encrypt_aes(aes_key, nonce, ticket_payload.encode())
        }

    def generate_ticket(self, client_id, server_id, key, creation_time, expiration_time):
        """
        generate tgt from given key
        :param expiration_time:
        :param creation_time:
        :param server_id: message server id
        :param key: AES Key used for encryption
        :param client_id: client initiated request
        :return: tgt
        """
        # ticket = f"{client_id}:{service_id}:{base64.b64encode(self.generate_salt()).decode()}"
        ticket = f"{self.version}|{client_id}|{server_id}"
        ticket += f"{creation_time}|{base64.b64encode(key).decode()}|{expiration_time}"
        return ticket

    def register(self, request):
        """
        These methods handle the registration of a client to the server
        :return: if the register succeeded
        """
        try:
            if request["name"] in self.get_clients_names():
                response = "Error, Name already exists!"
                return {
                    "code": 1601,
                    "version": self.version,
                    "payloadSize": len(response),
                    "payload": response
                }
            else:
                client_id = create_uuid()
                password_hash = create_password_sha(request["password"])
                self.clients.append(
                    {
                        "clientID": str(client_id),
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
                    "payload": str(client_id)
                }

        except Exception as e:
            print("register error: \n" + str(e))
            return "Error! can't add user because of {}".format(str(e))

    def receive_client_request(self, client_socket, addr):
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
            client_socket.send(json.dumps(response).encode("utf-8"))
        except Exception as e:
            print(f"Error when handling client: {e}")
        finally:
            client_socket.close()
            print(f"Connection to client ({addr[0]}:{addr[1]}) closed")

    def test_receive_client_request(self):
        """
        recieve request from client and parse it
        :return: parsed dict with the request
        """
        # temp
        client = name_generator()
        print(client)
        return client
        # return {
        #     "name": "alice",
        #     "Password": "Aa132465!",
        #     "encrypted_ticket": "encrypted_ticket_data",
        # }

    def handle_client_request(self, request):
        """
        handles the request from the client
        :param request: parsed dict of info
        :return: error code
        """
        # TODO: check if payload size matches the payload size header
        # TODO: check if version matches
        try:
            if not request:
                raise NameError("request is empty!")
            # Todo: print as json, add error handeling for json
            print(f"handle_client_request: \n{request}")
            code = request["header"]["code"]
            if code == 1024:
                try:
                    payload = json.loads(request["payload"])
                    return self.register(payload)
                except Exception as e:
                    raise ValueError("Payload is not valid JSON. \nPayload:{}\nError:{}".format(request["payload"], str(e)))
            if code == 1027:
                # TODO: separate function
                print("Client requested key")
                client_id = request["header"]["clientID"]
                nonce = request["payload"]["nonce"]
                response = self.generate_session_key(client_id,
                                                     self.message_server.get("uuid"), nonce)
                print("Created session key!")
                # try:
                #     print(json.dumps(dict(response)))
                # except ValueError as e:
                print(response)
                # TODO: check the encrypted key iv thing
                encrypted_key = {
                    "AES Key": encrypt_aes(response.get('key'), nonce, nonce),
                    "Nonce": encrypt_aes(response.get('key'), nonce, nonce),
                    "Encrypted Key IV": create_iv()
                }
                payload = {
                    "encrypted_key": encrypted_key,
                    "ticket": response.get('ticket')
                }
                # print(f"payload: \n{json.dumps(payload)}")
                print(f"payload: \n{payload}")
                return {
                    "header": {
                        "code": 1603,
                        "version": self.version,
                        "payloadSize": len(payload)
                    },
                    "payload": payload
                }
            return "Not supported yet!"
        except KeyError as e:
            print(f"Got Key Error on {e}")
            exit(1)
        except Exception as e:
            print("handle_client_request error: \n" + str(e))
            exit(1)

    def register_user(self):
        client_name_for_request = self.test_receive_client_request()
        if client_name_for_request:
            client_request = {
                "header": {
                    "code": 1024,  # register code
                    "version": self.version
                },
                "payload": client_name_for_request
            }
            response = self.handle_client_request(client_request)
            print(f"Server reply: {response}")
            return response
        return "Error"

    # Todo: move to tests file
    def test_server(self):
        response = self.register_user()
        while "Error" in response:
            response = self.register_user()

        print("------------------------------------------")
        client_id = response["payload"]
        client_request = {
            "header": {
                "code": 1027,  # register code
                "version": self.version,
                "clientID": client_id
            },
            "payload": {
                "serverID": self.message_server.get("uuid"),
                "nonce": create_nonce()
            }
        }
        client_request["header"]["payloadSize"] = len(client_request["payload"])
        print(json.dumps(client_request, indent=4, default=str))
        response = self.handle_client_request(client_request)
        print(f"Server reply: {response}")

    def start_server(self):
        """
        infinite loop of listening server
        :return:
        """
        # client_request = self.receive_client_request()
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

        # TODO: Use infinite loops again
        # while True:
        #     client_request = self.receive_client_request()
        #     if client_request:
        #         pass
        # TODO add support for multi servers using threads
        # thread = threading.Thread(target=self.handle_client_request, args=(client_request,))
        # thread.start()


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
