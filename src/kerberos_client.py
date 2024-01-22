class KerberosClient:
    def __init__(self):
        self.client_id = None
        self.secret_key = None

    def register(self, client_id, secret_key):
        self.client_id = client_id
        self.secret_key = secret_key

    def send_request_to_server(self, server):
        pass

