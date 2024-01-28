PORT_FILE = "port.info"
MESSAGE_SERVER_FILE = "msg.info"
PROTOCOL_VERSION = 24


def get_port():
    try:
        with open(PORT_FILE, 'r') as portfile:
            port = portfile.readline().strip()
            if port:
                return port
    except Exception as e:
        print(str(e))
        print("Going back to default port: 1256")
    finally:
        return 1256


# get_message_server_details. defaults to read but can write to it
# TODO add options to write to this file, create a new one maybe
def get_message_servers(write=False):
    msg_srv = {}
    flag = 'r'
    if write:
        flag = 'r+'
    try:
        with open(MESSAGE_SERVER_FILE, flag) as msg_srv_file:
            message_server = msg_srv_file.readlines()
            msg_srv["ip"] = message_server[0].split(':')[0]
            msg_srv["port"] = message_server[0].split(':')[1]
            msg_srv["name"] = message_server[1]
            msg_srv["uuid"] = message_server[2]
            msg_srv["key"] = message_server[3]
            return msg_srv
    except Exception as e:
        print(str(e))
        print("Can't open message server details")
        return default_msg_server()


def get_version():
    return PROTOCOL_VERSION


def default_msg_server():
    return {
        "ip": "127.0.0.1",
        "port": 1235,
        "name": "Printer 20",
        "uuid": "64f3f63985f04beb81a0e43321880182",
        "key": "MIGdMA0GCSqGSIb3DQEBA"
    }
