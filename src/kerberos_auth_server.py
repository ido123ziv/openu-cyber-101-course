import json
from datetime import datetime
# import threading
from shared_server import *
import base64
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from uuid import uuid1
CLIENT_FILE = "clients.info"
# todo use multiple message services for now leave it
SERVERS_FILE = "servers.info"


def create_uuid():
    return uuid1().int


def create_password_sha(password: str):
    sh = SHA256.new()
    sh.update(bytes(password, encoding='utf-8'))
    return sh.hexdigest()


class KerberosAuthServer:
    def __init__(self):
        self._clients = load_clients()
        self._port = get_port()
        self._version = get_version()
        self._message_sever = get_message_servers()
        self._servers = {}
        # self.lock = threading.Lock()

    @property
    def clients(self):
        return self._clients

    @property
    def port(self):
        return self._port

    @property
    def version(self):
        return self._version

    @property
    def servers(self):
        return self._servers

    @property
    def message_sever(self):
        return self._message_sever


    # TODO add a parsing to the client names
    def get_clients_names(self):
        return []

    def generate_session_key(self):
        pass

    # TODO add support for multi servers using threads
    def get_servers(self):
        pass

    def receive_client_request(self, request={}):
        # temp
        return {
            "Name": "alice",
            "Password": "Aa132465!",
            "encrypted_ticket": "encrypted_ticket_data",
        }

    def handle_client_request(self, request):
        # TODO add a check if client exists, if so return error
        if not request:
            return "Error"
        try:
            if request["Name"] in self.get_clients_names():
                return "Error"
            else:
                client_id = create_uuid()
                password_hash = create_password_sha(request["Password"])
                self.clients.append(
                    {
                        "ID": str(client_id),
                        "Name": request["Name"],
                        "PasswordHash": str(password_hash),
                        "LastSeen": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }
                )
                add_client_to_file(self.clients)

        except Exception as e:
            print(str(e))
            exit(1)

    def start_server(self):
        print(f"Server Started on port {self.port}")
        client_request = self.receive_client_request()
        if client_request:
            self.handle_client_request(client_request)

        # while True:
        #     client_request = self.receive_client_request()
        #     if client_request:
        #         pass
                # TODO add support for multi servers using threads
                # thread = threading.Thread(target=self.handle_client_request, args=(client_request,))
                # thread.start()


def load_clients():
    try:
        with open(CLIENT_FILE, 'r') as clients_file:
            clients = clients_file.readlines()
            if clients:
                return clients
    except Exception as e:
        print(str(e))
        print("No clients found")
    finally:
        return []


def add_client_to_file(clients):
    backup_client = load_clients()
    try:
        with open(CLIENT_FILE, 'w+') as clients_file:
            for client in clients:
                clients_file.write("ID: {} ".format(client["ID"]))
                clients_file.write("Name: {} ".format(client["Name"]))
                clients_file.write("PasswordHash: {} ".format(client["PasswordHash"]))
                clients_file.write("LastSeen: {}".format(client["LastSeen"]))
    except Exception as e:
        print(str(e))
        print("Couldn't add client, defaulting to previous state")
        with open(CLIENT_FILE, 'w') as clients_file:
            clients_file.writelines(backup_client)


def main():
    server = KerberosAuthServer()
    print(f"I'm a Kerberos Server!")
    print(f"my clients are: {server.clients}")
    print(f"using port: {server.port}")
    print(f"my version is {server.version}")
    print(f"message_sever in use: {server.message_sever}")
    print(f"my messaging servers {server.servers}")
    server.start_server()


if __name__ == "__main__":
    print("Hello World")
    main()
