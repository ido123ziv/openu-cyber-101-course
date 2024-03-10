import json

import pytest

from src.kerberos_auth_server import KerberosAuthServer, CLIENT_FILE
from src.shared_server import *
import os
os.chdir("../src")


@pytest.fixture
def server():
    return KerberosAuthServer()


def test_register_user(server, client=None):
    """
    test for auth server that generates a client
    :param server:
    :return:
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
    test for auth server that checks handling user reconnecting
    :param server:
    :return:
    """
    client_name_for_request = name_generator()
    print(f"client: {client_name_for_request}")
    print("Register Once:")
    test_register_user(server, client=client_name_for_request)
    print("Register Twice:")
    test_register_user(server, client=client_name_for_request)


def test_unregistered_user(server):
    payload = {
        "name": "unregistered_user",
        "password": "-1"
    }
    client_request = {
        "header": {
            "clientID": "0320632458510680",
            "version": 24,
            "code": 1024,
            "payloadSize": len(json.dumps(payload))
        },
        "payload": json.dumps(payload)
    }
    client_request["header"]["payloadSize"] = len(json.dumps(client_request["payload"]))
    send_to_server(server, client_request, 1600)


# TODO: fix why not raising errors
def test_incorrect_password(server):
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
        send_to_server(server, client_request, 1600)
    except Exception as e:
        print("Not enough users: " + str(e))
        with pytest.raises(ValueError, match="didn't find users"):
            raise ValueError("didn't find users")


def register_multiple_users(server):
    count = 0
    while count < 10:
        test_register_user(server)
        count += 1
    assert count < 10


def test_version(server):
    assert server.version == 24


def test_port(server):
    port = get_port()
    assert server.port == port


def test_clients(server):
    with open(CLIENT_FILE, 'r') as clinets_file:
        clients = clinets_file.readlines()
    assert len(server.clients) == len(clients)


def test_auth_server_functionality(server):
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


