from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import threading

class KerberosClient:
    def __init__(self):
        self.client_id = None
        self.secret_key = None

    def register(self, client_id, secret_key):
        self.client_id = client_id
        self.secret_key = secret_key

    def request_service_ticket(self, service_id):
        nonce = "67890"
        timestamp = "2024-01-14T12:01:00"
        request = {
            "client_id": self.client_id,
            "timestamp": timestamp,
            "nonce": nonce,
            "service_id": service_id,
        }

        thread = threading.Thread(target=self.send_request_to_server, args=(request,))
        thread.start()

    def send_request_to_server(self, request):
        server_response = self.receive_server_response(request)
        if "error" in server_response:
            print(f"Error from server: {server_response['error']}")
            return

        decrypted_response = self.decrypt_aes(server_response["encrypted_response"], self.secret_key)
        session_key = eval(decrypted_response)["session_key"]

        print(f"Got the session key for secure communication with the service: {session_key}")

    def receive_server_response(self, request):
        # Simulate sending the request to the Kerberos server
        # In a real-world scenario, you would use a network library to send the request
        # and receive the response from the server
        server = KerberosServer()  # Instantiate a server for simulation
        return server.handle_client_request(request)

    def decrypt_aes(self, encrypted_data, key):
        data = base64.b64decode(encrypted_data)
        iv, ciphertext = data[:16], data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return decrypted_data

def main():
    client = KerberosClient()
    client.register("alice", get_random_bytes(32))  # Simulated secret key for Alice
    service_ids = ["service1", "service2", "service3"]

    for service_id in service_ids:
        client.request_service_ticket(service_id)

    # Ensure all threads complete before exiting
    main_thread = threading.current_thread()
    for thread in threading.enumerate():
        if thread is not main_thread:
            thread.join()

if __name__ == "__main__":
    main()
