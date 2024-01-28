import time
import threading
from shared_server import *
CLIENT_FILE="clients.info"
SERVERS_FILE="servers.info"


class KerberosAuthServer:
    def __init__(self, port: int, clients: list):
        self.clients = clients
        self.port = port
        self.servers = {}
        self.lock = threading.Lock()

    def generate_session_key(self):
        pass

    def get_servers(self):
        pass

    def receive_client_request(self):
        pass

    def handle_client_request(self):
        pass

    def start_server(self):
        while True:
            client_request = self.receive_client_request()
            if client_request:
                thread = threading.Thread(target=self.handle_client_request, args=(client_request,))
                thread.start()


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


def main():
    clients = load_clients()
    port = get_port()
    server = KerberosAuthServer(port, clients)
    server.start_server()


if __name__ == "__main__":
    print("Hello World")
    main()