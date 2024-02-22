import pytest

from src.kerberos_client import KerberosClient
from shared_server import *


@pytest.fixture
def client():
    return KerberosClient()
 
def test_version(client):
    assert client.version == 24

def test_client_functionality(client):
    client.register("Name")
    client.send_message("Some Message.")
