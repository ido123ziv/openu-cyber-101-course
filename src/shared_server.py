PORT_FILE = "port.info"
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


def get_version():
    return PROTOCOL_VERSION
