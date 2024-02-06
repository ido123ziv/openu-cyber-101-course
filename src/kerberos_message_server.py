import threading
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
    """
    represents a kerberos message server
    """

    # def __init__(self, port: int, name: str, uuid: str, key):
    def __init__(self):
        """
        constructor
        """
        try:
            server = get_message_servers()
            self._port = server["port"]
            self._name = server["name"]
            self._uuid = server["uuid"]
            self._version = get_version()
            self._key = base64.b64decode(server["key"])
            self._lock = threading.Lock()
            self._clients = {}
        except Exception as e:
            print(str(e))
            default_error()

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
            authenticator = request("authenticator")
            aes_key = ticket.decode().split('|')[-2:-1]
            auth_data = decrypt_aes(authenticator, self.key)
            self._clients.add({
                "client_id": auth_data['clientID'],
                "key": aes_key,
                "auth_iv": auth_data["authenticatorIV"]
            })
            return dict(Code=1604)
        except Exception as e:
            print(str(e))
            return default_error()

    def find_client_by_iv(self, message_iv):
        """
        This method finds a client in the list by the IV given
        :param message_iv: IV used for encrypting the ticket
        :return: client details, {} if error found
        """
        try:
            clients_ivs = [x.get("auth_iv") for x in self._clients]
            ind = clients_ivs.index(message_iv)
            return self._clients[ind]
        except ValueError as e:
            print("Client Not registered")
            return {}
        except IndexError as e:
            print("Client not in list")
            return {}

    def print_message(self, request):
        """
        Prints a user message
        :param request: a dict with message details
        :return: success code
        """
        try:
            # TODO: check if message size matches the payload
            message = request["messageContent"]
            client_key = self.find_client_by_iv(request["messageIV"])
            if client_key == {}:
                raise ValueError("User Not Found")
            decrypted_message = decrypt_aes(message, client_key)
            print(decrypted_message)
            return dict(Code=1605)
        except Exception as e:
            print(str(e))
            return default_error()

    def receive_client_request(self, request={}):
        """
        Generates temporarily client
        :param request:
        :return: client name
        """
        if request is None or request == {}:
            client = name_generator()
        else:
            client = request.get('client')
        print(f"see client: {client}")
        return client
        # self.get_and_decrypt_key()
        # self.print_message()

    def handle_client_request(self, request):
        """
        Handles servers request from clients by determinate error codes
        :param request: dict of object from user
        :return: success code
        """
        try:
            if not request:
                raise NameError("request is empty!")
            code = request["header"]["code"]
            if code == 1028:
                return self.get_and_decrypt_key(request["payload"])
            elif code == 1029:
                return self.print_message(request["payload"])
            else:
                raise ValueError("Not Valid request code")
        except Exception as e:
            print(str(e))
            return {"code": default_error()}

    def start_server(self):
        """
        infinite loop, listening to requests from clients
        :return:
        """
        # TODO: add methods to check this
        print(f"Server started on port: {self.port}")
        client = self.receive_client_request()

        pass
        # while True:
        #     client_request = self.receive_client_request()
        #     if client_request:
        #         thread = threading.Thread(target=self.handle_client_request, args=(client_request,))
        #         thread.start()


def main():
    """
    creates an instance of messaging server
    :return:
    """
    server = KerberosMessageServer()
    print("I'm a messages server!")
    print(f"My name is {server.name}")
    print(f"Port: {server.port}")
    print(f"Version: {server.version}")
    print(f"my uuid is {server.uuid}")
    print(f"my key is {server.key}")
    server.start_server()


if __name__ == "__main__":
    print("Hello World")
    main()

