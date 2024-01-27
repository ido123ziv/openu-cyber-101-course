import base64
import threading
from shared_server import *
SERVER_FILE = "msg.info"


def default_error():
    print("server responded with an error")
    exit(1)


def message_keys(key: int):
    switcher = {
        0: "port",
        1: "name",
        2: "uuid",
        3: "key"
    }
    return switcher.get(key, -1)


# def read_server():
#     try:
#         with open(SERVER_FILE, 'r') as server_file:
#             data = server_file.readlines()
#             server_data = {"port": get_port()}
#             for i in range(len(data)):
#                 data_key = message_keys(i)
#                 if i != -1:
#                     server_data[data_key] = data[i]
#                 else:
#                     raise Exception("Corrupted message file")
#             return server_data
#     except Exception as e:
#         print(str(e))
#         print("Going back to default port: 1256")
#         default_error()


class KerberosMessageServer:
    # def __init__(self, port: int, name: str, uuid: str, key):
    def __init__(self):
        try:
            server = get_message_servers()
            self.port = server["port"]
            self.name = server["name"]
            self.uuid = server["uuid"]
            self.key = server["key"]
            self.lock = threading.Lock()
        except Exception as e:
            print(str(e))
            default_error()

    def get_and_decrypt_key(self):
        pass

    def print_message(self):
        pass

    def receive_client_request(self):
        self.get_and_decrypt_key()
        self.print_message()
        pass

    def start_server(self):
        while True:
            client_request = self.receive_client_request()
            if client_request:
                thread = threading.Thread(target=self.handle_client_request, args=(client_request,))
                thread.start()