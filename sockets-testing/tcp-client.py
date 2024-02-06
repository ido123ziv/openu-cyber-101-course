import socket
import struct

def send_message(message):
    # Create a TCP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Connect to the server
        client_socket.connect(('127.0.0.1', 8888))

        # Send a simple text message to the server
        message_data = struct.pack('!I', len(message)) + message.encode('utf-8')
        client_socket.send(message_data)

        # Receive the response from the server
        response_data = client_socket.recv(1024)
        response_length = struct.unpack('!I', response_data[:4])[0]
        response = response_data[4:].decode('utf-8')

        print(f"Server response: {response}")
    finally:
        # Close the client socket
        client_socket.close()

if __name__ == "__main__":
    message_to_send = "Hello, server! How are you?"
    send_message(message_to_send)
