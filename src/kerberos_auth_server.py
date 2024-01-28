import json
import time
# import threading
from shared_server import *
CLIENT_FILE = "clients.info"
# todo use multiple message services for now leave it
SERVERS_FILE = "servers.info"


class KerberosAuthServer:
    def __init__(self):
        self.clients = load_clients()
        self.port = get_port()
        self.version = get_version()
        self.message_sever = get_message_servers()
        self.servers = {}
        # self.lock = threading.Lock()

    # TODO add a parsing to the client names
    def get_clients_names(self):
        return []

    def generate_session_key(self):
        pass

    # TODO add support for multi servers using threads
    def get_servers(self):
        pass

    def create_uuid(self):
        pass

    def receive_client_request(self, request={}):
        # temp
        return {
            "client_id": "alice",
            "timestamp": "2024-01-14T12:00:00",
            "nonce": "12345",
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
                client_id = self.create_uuid()
                self.clients.append(
                    json.dumps({
                        "ID": client_id,
                        "Name": request["Name"],
                        "PasswordHash": request["PasswordHash"],
                        "LastSeen": time.localtime()
                    })
                )
                add_client_to_file(self.clients)

        except Exception as e:
            print(str(e))
            return "Error"
        pass
        pass

    def start_server(self):
        while True:
            client_request = self.receive_client_request()
            if client_request:
                pass
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
            clients_file.writelines(clients)
    except Exception as e:
        print(str(e))
        print("Couldn't add client, defaulting to previous state")
        with open(CLIENT_FILE, 'w') as clients_file:
            clients_file.writelines(backup_client)


def main():
    server = KerberosAuthServer()
    server.start_server()


if __name__ == "__main__":
    print("Hello World")
    main()
