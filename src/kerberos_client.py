from kerberos_auth_server import KerberosAuthServer as authserver
CLIENT_FILE = "me.info"

class KerberosClient:
    def __init__(self):
        self.name = None
        self.uuid = None
        self.aes_key = None
        self.ticket = None

    def register(self, username):
        try:
            with open(CLIENT_FILE, 'r') as client_file:
                data = client_file.readlines()
                name = data[0]
                uuid = data[1]
        except FileNotFoundError:
            username = input("Enter username: ")
            name, uuid = authserver.register_client(username)
            self.name = name
            self.uuid = uuid

        with open(CLIENT_FILE, 'w') as client_file:
            client_file.writelines([name, uuid])

    def receive_aes_key(self):
        encrypted_key, ticket = authserver.generate_session_key()
        decrypted_key = decrypt_aes(encrypted_key,)
        # where to save them?
        # self.aes_key = decrypted_key
        # self.ticket = ticket

    def send_aes_key(self):
        pass

    def send_message(self):
        pass
