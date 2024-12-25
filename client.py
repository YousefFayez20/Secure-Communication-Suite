import socket

from crypto.ca import validate_certificate
from utils.auth import authenticate_user
from utils.keys import generate_aes_key
from crypto.aes import AESHandler
from crypto.hash import compute_sha256
from crypto.rsaEnDe import RSAHandler
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding  # Correct import
from cryptography.hazmat.primitives import hashes


def start_client():

    while True:
    # Authenticate user
        username = input("Enter your username: ").strip()
        password = input("Enter your password: ").strip()

        if not authenticate_user(username, password):
            print("Login failed.")
            continue
        else:
            break
    # Validate the server's certificate(Not Complete Implementation)
    ca_cert_path = "crypto/certificates/ca_cert.pem"
    server_cert_path = "crypto/certificates/server_cert.pem"

    if not validate_certificate(server_cert_path, ca_cert_path):
        print("Server certificate validation failed. Exiting...")
        return

    print("Server certificate validated successfully.")

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("localhost", 12345))
    # Load server's public key
    with open("server_public.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    # Generate AES key
    aes_key = generate_aes_key()

    while True:
        # Prompt the user for the message they want to send
        message = input("Enter the message you want to send: ").strip()

        # Predefined IV for AES encryption (you could also generate it randomly if needed)
        iv = b"RandomIV12345678"
        aes_handler = AESHandler(aes_key, iv)

        # Encrypt the message using AES
        encrypted_message = aes_handler.encrypt(message)
        print(f"Encrypted Message (AES): {encrypted_message.hex()}")

        # Encrypt AES key with the server's RSA public key
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Encrypt the username for confidentiality (optional)
        encrypted_username = public_key.encrypt(
            username.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Compute hash of the message for integrity verification
        message_hash = compute_sha256(message)

        # Send the data to the server


        # Send encrypted AES key, encrypted username, encrypted message, and the message hash
        client_socket.send(
            encrypted_aes_key + b"||" + encrypted_username + b"||" + encrypted_message + b"||" + message_hash.encode())

        print(f"Message sent to the server: {message}")
    # client_socket.close()


# Client-side entry point
if __name__ == "__main__":
    start_client()