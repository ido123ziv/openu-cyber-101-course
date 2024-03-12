from src.kerberos_client import KerberosClient
from src.shared_server import *

import pytest
import os

CLIENT_FILE = "me.info"


@pytest.fixture
def client():
    return KerberosClient()
 

def test_version(client):
    assert client.version == 24


def test_register_new_client(client):
    """
    Test registration when client doesn't exist.
    """
    if os.path.exists(CLIENT_FILE):
        os.remove(CLIENT_FILE)

    client.register()


def test_register(client):
    """
    Test registration when client exists.
    """
    with open(CLIENT_FILE, 'w') as client_file:
        username = "someusername"
        uuid = "3f63985f04beb81a"
        client_file.writelines([username, uuid])

    client.register()


def test_send_message(client):
    client.send_message_for_print("gaga")


def test_send_key_to_server(client):
    client.send_aes_key()

