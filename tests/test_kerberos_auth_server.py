import json

import pytest

from src.kerberos_auth_server import KerberosAuthServer, CLIENT_FILE
from src.shared_server import *
import os
os.chdir("../src")


@pytest.fixture
def server():
    return KerberosAuthServer()


# def test_main(server):
#     server.start_server()
def test_register_user(server):
    """
    test for auth server that generates a client
    :param server:
    :return:
    """
    client_name_for_request = name_generator()
    print(client_name_for_request)
    if client_name_for_request:
        client_request = {
            "header": {
                "code": 1024,  # register code
                "version": 24
            },
            "payload": json.dumps(client_name_for_request)
        }
        response = server.handle_client_request(client_request)
        if not response:
            assert False
        try:
            print(f"Server reply: {json.dumps(response)}")
        except Exception as e:
            print(str(e))
            print(f"Server reply: {response}")
        assert True
    else:
        assert False


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
    client_id = "55333695485370013835749364635449140321"
    payload = {
            "serverID": "64f3f63985f04beb81a0e43321880182",
            "nonce": str(create_nonce())
        }
    client_request = {
        "header": {
            "code": 1027,  # register code
            "version": 24,
            "clientID": client_id
        },
        "payload": json.dumps(payload)
    }
    client_request["header"]["payloadSize"] = len(json.dumps(client_request["payload"]))
    print(json.dumps(client_request, indent=4, default=str))
    response = server.handle_client_request(client_request)
    print(f"Server reply: {response}")




# test needed:
# TODO:
"""
register a client
terminate server and see if clients are reserved
generate a key
client that is already registered can't re-register
"""