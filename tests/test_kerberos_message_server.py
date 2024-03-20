from src.kerberos_message_server import KerberosMessageServer
from src.shared_server import *

import pytest
import os
os.chdir("../src")


def get_message_servers(write=False):
    msg_srv = {}
    flag = 'r'
    if write:
        flag = 'r+'
    try:
        with open(MESSAGE_SERVER_FILE, flag) as msg_srv_file:
            message_server = msg_srv_file.readlines()
            msg_srv["ip"] = message_server[0].split(':')[0]
            msg_srv["port"] = message_server[0].split(':')[1].strip()
            msg_srv["name"] = message_server[1].strip()
            msg_srv["uuid"] = message_server[2].strip()
            msg_srv["key"] = message_server[3].strip()
            return msg_srv
    except Exception as e:
        print(str(e))
        print("Can't open message server details")
        return default_msg_server()
    
    
@pytest.fixture
def server():
    return KerberosMessageServer()


@pytest.fixture
def messages():
    return get_message_servers()


def test_version(server):
    assert server.version == 24


def test_port(server, messages):
    assert int(messages.get("port")) == server.port


def test_uuid(server, messages):
    assert messages.get("uuid") == server.uuid
