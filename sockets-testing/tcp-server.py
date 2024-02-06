import socket
import threading
import struct


def handle_client(client_socket):
    try:
        # Receive data from the client
        data = client_socket.recv(1024)

        if data:
            # Assuming the data received is a simple text message
            message_length = struct.unpack('!I', data[:4])[0]
            message = data[4:].decode('utf-8')

            print(f"Received message from client: {message}")

            # Respond to the client
            response = "Hello from the server!"
            response_data = struct.pack('!I', len(response)) + response.encode('utf-8')
            client_socket.send(response_data)
    finally:
        # Close the client socket
        client_socket.close()


def start_server():
    # Create a TCP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to a specific address and port
    server_socket.bind(('127.0.0.1', 8888))

    # Listen for incoming connections
    server_socket.listen(5)
    print("Server listening on port 8888...")

    try:
        while True:
            # Accept a new connection
            client_socket, client_address = server_socket.accept()
            print(f"Accepted connection from {client_address}")

            # Start a new thread to handle the client
            client_handler = threading.Thread(target=handle_client, args=(client_socket,))
            client_handler.start()
    except KeyboardInterrupt:
        print("Server shutting down.")
    finally:
        # Close the server socket
        server_socket.close()


if __name__ == "__main__":
    start_server()
