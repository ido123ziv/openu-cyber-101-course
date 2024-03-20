from src.kerberos_auth_server import KerberosAuthServer, CLIENT_FILE
from src.shared_server import *

import pytest
import json
import os
os.chdir("../src")


@pytest.fixture
def server():
    return KerberosAuthServer()


def name_generator():
    """
    :return: generated random name and password.
    """
    name = ''.join(random.choices(string.ascii_lowercase, k=random.randint(3, 5)))
    password = name[0].upper() + name[0].lower() + "123456!"
    return {"name": name, "password": password}


def test_register_user(server, client=None):
    """
    test for auth server that generates a client and registers it.
    :param server: auth server.
    :param client: a client.
    """
    if client is None:
        client_name_for_request = name_generator()
    else:
        client_name_for_request = client
    print(client_name_for_request)
    if client_name_for_request:
        client_request = {
            "header": {
                "clientID": "client_id87654321",
                "code": 1024,  # register code
                "version": 24,
                "payloadSize": len(json.dumps(client_name_for_request))
            },
            "payload": json.dumps(client_name_for_request)
        }
        response = server.handle_client_request(client_request)
        if not response:
            assert False
        try:
            print(f"Server reply: {json.dumps(response)}")
            assert True
        except Exception as e:
            print(str(e))
            print(f"Server reply: {response}")
            raise pytest.raises(e)
    else:
        assert False


def test_re_register_user(server):
    """
    test for auth server that checks handling user reconnecting.
    :param server: auth server.
    """
    client_name_for_request = name_generator()
    print(f"client: {client_name_for_request}")
    print("Register Once:")
    test_register_user(server, client=client_name_for_request)
    print("Register Twice:")
    test_register_user(server, client=client_name_for_request)


def test_unregistered_user(server):
    """
    :param server: auth server.
    """
    payload = {
        "name": "unregistered_user",
        "password": "-1"
    }
    client_request = {
        "header": {
            "clientID": "000000000000000",
            "version": 24,
            "code": 1024,
            "payloadSize": len(json.dumps(payload))
        },
        "payload": json.dumps(payload)
    }
    client_request["header"]["payloadSize"] = len(json.dumps(client_request["payload"]))
    send_to_server(server, client_request, 1601)


def test_incorrect_password(server):
    """
    test for auth server that checks registration attempt with wrong password.
    :param server: auth server.
    """
    try:
        clients = server.clients()
        client = clients.keys()[0]
        payload = {
            "name": client["name"],
            "password": "-1"
        }
        client_request = {
            "header": {
                "clientID": client["clientID"],
                "version": 24,
                "code": 1024,
                "payloadSize": len(json.dumps(payload))
            },
            "payload": json.dumps(payload)
        }
        client_request["header"]["payloadSize"] = len(json.dumps(client_request["payload"]))
        send_to_server(server, client_request, 1601)
    except Exception as e:
        print("Not enough users: " + str(e))
        with pytest.raises(ValueError, match="didn't find users"):
            raise ValueError("didn't find users")


def register_multiple_users(server):
    """
    
    """
    count = 0
    while count < 10:
        test_register_user(server)
        count += 1
    assert count < 10


def test_version(server):
    """
    test for auth server that checks the server version.
    :param server: auth server.
    """
    assert server.version == 24


def test_port(server):
    """
    test for auth server that checks the port number.
    :param server: auth server.
    """
    port = get_port()
    assert server.port == port


def test_clients(server):
    """
    test for auth server that checks the number of the clients.
    :param server: auth server.
    """
    with open(CLIENT_FILE, 'r') as clinets_file:
        clients = clinets_file.readlines()
    assert len(server.clients) == len(clients)


def test_auth_server_functionality(server):
    """
    test for auth server that checks its functionality. 
    :param server: auth server.
    """
    print("------------------------------------------")
    payload = {
            "serverID": "64f3f63985f04beb81a0e43321880182",
            "nonce": str(create_nonce())
        }
    client_request = {
        "header": {
            "code": 1027,  # register code
            "version": 24,
            "clientID": "55333695485370013835749364635449140321"
        },
        "payload": json.dumps(payload)
    }
    client_request["header"]["payloadSize"] = len(json.dumps(client_request["payload"]))
    send_to_server(server, client_request, 1603)


def send_to_server(server, client_request: dict, desired_code: int):
    """
    sends request to auth server.
    :param client_request: request.
    :param desired_code: the request code.
    """
    try:
        print("request: \n" + json.dumps(client_request, indent=4, default=str))
        response = server.handle_client_request(client_request)
        print(f"Server reply: \n{response}")
        if "header" in response.keys():
            code = response["header"]["code"]
        elif "code" in response.keys():
            code = response["code"]
        else:
            raise ValueError("Invalid Server Response")
        assert code == desired_code
    except Exception as e:
        print("Unhandled Exception: " + str(e))
        assert False


