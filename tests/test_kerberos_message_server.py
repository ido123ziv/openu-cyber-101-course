import pytest

from src.kerberos_message_server import KerberosMessageServer
from src.shared_server import *
import os
os.chdir("../src")


@pytest.fixture
def server():
    return KerberosMessageServer()


@pytest.fixture
def messages():
    return get_message_servers()


def test_version(server):
    assert server.version == 24


def test_port(server, messages):
    assert messages.get("port") == server.port


def test_uuid(server, messages):
    assert messages.get("uuid") == server.uuid


# def test_main(server):
#     server.start_server()


# Todo: Add checks if ports match as test
