import json
import random
from datetime import datetime, timedelta

from Crypto.Util.Padding import pad, unpad

# import threading
from shared_server import *
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from uuid import uuid1
import string
CLIENT_FILE = "clients.info"
# todo use multiple message services for now leave it
SERVERS_FILE = "servers.info"


def name_generator():
    orig = 'klmnopqrstuvwxyza'
    for let in orig:
        ind = orig.index(let)
        suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=3))
        try:
            print(f"{ind + 10}: " + "{\"Name\": \"" + let + f"{suffix}\", \"Password\": \"" + orig[ind].upper() + orig[
                ind + 1] + "123456!\"},")
        except Exception as e:
            print("26: {Name\": \"zina\", \"Password\": \"Za123456!}")


def get_name_and_password():
    key = random.randrange(0, 26)
    switcher = {
        0: {"Name": "alice", "Password": "Ab123456!"},
        1: {"Name": "bob", "Password": "Bc123456!"},
        2: {"Name": "charile", "Password": "Cd123456!"},
        3: {"Name": "david", "Password": "De123456!"},
        4: {"Name": "ego", "Password": "Ef123456!"},
        5: {"Name": "foxi", "Password": "Fg123456!"},
        6: {"Name": "grant", "Password": "Gh123456!"},
        7: {"Name": "homer", "Password": "Hi123456!"},
        8: {"Name": "ivan", "Password": "Ij123456!"},
        9: {"Name": "jake", "Password": "Jk123456!"},
        10: {"Name": "kI29", "Password": "Kl123456!"},
        11: {"Name": "lDVP", "Password": "Lm123456!"},
        12: {"Name": "mV0B", "Password": "Mn123456!"},
        13: {"Name": "n2PK", "Password": "No123456!"},
        14: {"Name": "oP0K", "Password": "Op123456!"},
        15: {"Name": "pCUX", "Password": "Pq123456!"},
        16: {"Name": "qO3V", "Password": "Qr123456!"},
        17: {"Name": "r4LO", "Password": "Rs123456!"},
        18: {"Name": "s27Q", "Password": "St123456!"},
        19: {"Name": "tLJG", "Password": "Tu123456!"},
        20: {"Name": "uVJO", "Password": "Uv123456!"},
        21: {"Name": "vAO2", "Password": "Vw123456!"},
        22: {"Name": "wT49", "Password": "Wx123456!"},
        23: {"Name": "x2Q2", "Password": "Xy123456!"},
        24: {"Name": "yURB", "Password": "Yz123456!"},
        25: {"Name": "z8SE", "Password": "Za123456!"},
        26: {"Name": "zina", "Password": "Za123456!"}
    }
    return switcher.get(key)


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

    # TODO add support for multi servers using threads
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
        """
        getting a list of names from current client list
        :return: a list of all client names
        """
        return [x["Name"] for x in self.clients]

    def generate_session_key(self, client_id, server_id, nonce):
        """
        :param nonce: random value created by the client
        :param server_id: messaging server id
        :param client_id: client id of user initiated the request
        :return: a tuple of AES Key and ticket encrypted
        """
        clients_ids = [x["ID"] for x in self.clients]
        client_index = clients_ids.index(client_id)
        client = self.clients[client_index]
        key = client.get("PasswordHash")
        bytes_key = str(key).encode()[32:]
        print(f"bytes: {bytes_key}, len: {len(bytes_key)}")
        aes_key = AES.new(bytes_key, AES.MODE_CBC, iv=create_iv())
        ticket_aes_key = encrypt_aes(aes_key, nonce, bytes_key)
        # aes_key = AES.new(get_random_bytes(32), AES.MODE_CBC, iv=get_random_bytes(16))
        ticket_payload = self.generate_ticket(client_id, server_id, ticket_aes_key)
        return {
            "key": aes_key,
            "ticket": encrypt_aes(aes_key, nonce, ticket_payload.encode())
        }

    def generate_ticket(self, client_id, server_id, key):
        """
        generate tgt from given key
        :param server_id: message server id
        :param key: AES Key used for encryption
        :param client_id: client initiated request
        :return: tgt
        """
        creation_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        expiration_time = (datetime.now() + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')
        # ticket = f"{client_id}:{service_id}:{base64.b64encode(self.generate_salt()).decode()}"
        ticket = f"{self.version}:{client_id}:{server_id}"
        ticket += f"{creation_time}:{base64.b64encode(key).decode()}:{expiration_time}"
        # TODO: encrypt the expiration time
        return ticket

    def register(self, request):
        """
        These methods handle the registration of a client to the server
        :return: if the register succeeded
        """
        try:
            if request["Name"] in self.get_clients_names():
                return "Error, Name already exists!"
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
                return {
                    "Code": 1600,
                    "Version": self.version,
                    "Payload size": len(str(client_id)),
                    "Payload": str(client_id)
                }

        except Exception as e:
            print(str(e))
            return "Error! can't add user because of {}".format(str(e))

    def receive_client_request(self, request={}):
        """
        recieve request from client and parse it
        :param request: a dict of info
        :return: parsed dict with the request
        """
        # temp
        client = get_name_and_password()
        print(client)
        return client
        # return {
        #     "Name": "alice",
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
            code = request["Header"]["Code"]
            if code == 1024:
                return self.register(request["Payload"])
            if code == 1027:
                print("Client requested key")
                client_id = request["Header"]["ID"]
                nonce = request["Payload"]["nonce"]
                response = self.generate_session_key(client_id,
                                                     self.message_sever.get("uuid"), nonce)
                print("Created session key!")
                # try:
                #     print(json.dumps(dict(response)))
                # except ValueError as e:
                print(response)
                # TODO: check the encrypted key iv thing
                encrypted_key = {
                    "AES Key": encrypt_aes(response.get('key'), nonce, nonce),
                    "Nonce": encrypt_aes(response.get('key'), nonce, nonce),
                    "Encrypted Key IV": ""
                }
                payload = {
                    "encrypted_key": encrypted_key,
                    "ticket": response.get('ticket')
                }
                # print(f"Payload: \n{json.dumps(payload)}")
                print(f"Payload: \n{payload}")
                return {
                    "Header": {
                        "Code": 1603,
                        "Version": self.version,
                        "Payload Size": len(payload)
                    },
                    "Payload": payload
                }
            return "Not supported yet!"
        except KeyError as e:
            print(f"Got Key Error on {e}")
            exit(1)
        except Exception as e:
            print(str(e))
            exit(1)

    def register_user(self):
        client_name_for_request = self.receive_client_request()
        if client_name_for_request:
            client_request = {
                "Header": {
                    "Code": 1024,  # register code
                    "Version": 24
                },
                "Payload": client_name_for_request
            }
            response = self.handle_client_request(client_request)
            print(f"Server reply: {response}")
            return response
        return "Error"

    def start_server(self):
        """
        infinite loop of listening server
        :return:
        """
        print(f"Server Started on port {self.port}")
        # client_request = self.receive_client_request()
        response = self.register_user()
        while "Error" in response:
            response = self.register_user()

        print("------------------------------------------")
        client_id = response["Payload"]
        client_request = {
            "Header": {
                "Code": 1027,  # register code
                "Version": 24,
                "ID": client_id
            },
            "Payload": {
                "server_id": self.message_sever.get("uuid"),
                "nonce": create_nonce()
            }
        }
        client_request["Header"]["Payload Size"] = len(client_request["Payload"])
        print(json.dumps(client_request, indent=4, default=str))
        response = self.handle_client_request(client_request)
        print(f"Server reply: {response}")


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
