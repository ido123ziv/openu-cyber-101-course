import getopt
import os
import sys

sys.path.insert(0,
                os.path.dirname(os.path.abspath("src/kerberos_auth_server.py")))

from src.kerberos_auth_server import main as server
from src.kerberos_client import main as client

del sys.path[0]


def main(argv):
    try:
        opts, args = getopt.getopt(argv, "h:c:s:", ["client", "server"])
    except getopt.GetoptError:
        print('main.py -c [--client]\nOR\nmain.py -s [--server]')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print('main.py -c [--client] to run this project client mode')
            print('main.py -s [--server] to run this project server mode')
            sys.exit()
        elif opt in ("-c", "--client"):
            client()
        elif opt in ("-s", "--server"):
            os.chdir("src")
            server()


if __name__ == "__main__":
    main(sys.argv[1:])
