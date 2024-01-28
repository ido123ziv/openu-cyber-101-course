import json

CLIENT_FILE = "me.info"
# TODO every error from server will return default error
class KerberosClient:
    def __init__(self, needToRegiste=False):
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


def read_write_client_details(write=False, client_data={}):
    flag = 'r'
    if write:
        flag = 'w+'
    try:
        if not write:
            with open(CLIENT_FILE, flag) as client_file:
                return json.load(client_file)
        else:
            with open(CLIENT_FILE, flag) as client_file:
                client_file.write(json.dumps(client_data))
    except Exception as e:
        print(str(e))
        return ""


def main():
    existing_client = read_write_client_details()
    register = False
    if not existing_client:
        name = input("Please enter your name: ")
        register = True
    else:
        name = existing_client.get("Name")
    client = KerberosClient(name, register)



if __name__ == "__main__":
    print("Hello World")
    main()
