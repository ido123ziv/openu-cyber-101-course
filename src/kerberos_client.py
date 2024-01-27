import json

CLIENT_FILE = "me.info"

class KerberosClient:
    def __init__(self):
        # TODO add support for creating a client or reading client data from file
        self.client_id = None
        self.secret_key = None

    def register(self, client_id, secret_key):
        self.client_id = client_id
        self.secret_key = secret_key

    def send_request_to_server(self, server):
        pass

    def request_key(self):
        pass


def read_write_client_details(client_data={}):
    try:
        with open(CLIENT_FILE, 'r') as client_file:
            return client_file.read()
    except Exception as e:
        print(str(e))
        with open(CLIENT_FILE, 'w+') as client_file:
            client_file.write(json.dumps(client_data))
