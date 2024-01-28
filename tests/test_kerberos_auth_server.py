import pytest

from src.kerberos_auth_server import KerberosAuthServer, CLIENT_FILE
from src.shared_server import *
import os
os.chdir("../src")


@pytest.fixture
def server():
    return KerberosAuthServer()


def test_main(server):
    server.start_server()


def test_version(server):
    assert server.version == 24


def test_port(server):
    port = get_port()
    assert server.port == port


def test_clients(server):
    with open(CLIENT_FILE, 'r') as clinets_file:
        clients = clinets_file.readlines()
    assert len(server.clients) == len(clients)


# test needed:
"""
register a client
terminate server and see if clients are reserved
generate a key
client that is already registered can't re-register
"""