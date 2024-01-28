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
    """creates uuid for each request, represent a client"""
    return uuid1().int


def create_password_sha(password: str):
    """
    creates a sha256 from a given password
    :param password: string representing a password
    :return: a sha256 of the password
    """
    sh = SHA256.new()
    sh.update(bytes(password, encoding='utf-8'))
    return sh.hexdigest()


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
        self._version = get_version()
        self._message_sever = get_message_servers()
        self._servers = {}
        # self.lock = threading.Lock()

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

    @property
    def servers(self):
        """
        getter for servers property 
        :return: a list of message servers
        """
        return self._servers

    @property
    def message_sever(self):
        """
        getter for message_sever property 
        :return: dict of current message server info
        """
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
        """
        recieve request from client and parse it
        :param request: a dict of info
        :return: parsed dict with the request
        """
        # temp
        return {
            "Name": "alice",
            "Password": "Aa132465!",
            "encrypted_ticket": "encrypted_ticket_data",
        }

    def handle_client_request(self, request):
        """
        handles the request from the client
        :param request: parsed dict of info
        :return: error code
        """
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
        """
        infinite loop of listening server
        :return:
        """
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
                ID: 219612343443330567787200566001537885281 Name: alice PasswordHash: 8a5eba0ab714cbcd4f314334f073c446c3092192de2e40271203a722f41648a5 LastSeen: 2024-01-28 22:34:33
                """
                client = row.split(" ")
                clients.append({
                    "ID": client[1],
                    "Name": client[3],
                    "PasswordHash": client[5],
                    "LastSeen": client[7] + " " + client[8].strip()
                })
            return clients
    except Exception as e:
        print(str(e))
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
                clients_file.write("ID: " + client.get("ID"))
                clients_file.write(" Name: " + client.get("Name"))
                clients_file.write(" PasswordHash: " + client.get("PasswordHash"))
                clients_file.write(" LastSeen: " + client.get("LastSeen") + "\n")
    except Exception as e:
        print(str(e))
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
    print(f"message_sever in use: {server.message_sever}")
    print(f"my messaging servers {server.servers}")
    server.start_server()


if __name__ == "__main__":
    print("Hello World")
    main()
