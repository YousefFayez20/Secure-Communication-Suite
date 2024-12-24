import os
import socket

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from crypto.ca import validate_certificate
from utils.auth import generate_user_certificate
from utils.keys import generate_rsa_keys
from crypto.aes import AESHandler
from crypto.hash import compute_sha256
from crypto.rsaEnDe import RSAHandler
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding

from crypto.ca import create_ca, save_certificate

def create_server_keys():
    """Generate server's RSA key pair, save the public key, and create a server certificate."""
    private_key_file = "server_private.pem"
    public_key_file = "server_public.pem"
    server_cert_path = "crypto/certificates/server_cert.pem"
    ca_cert_path = "crypto/certificates/ca_cert.pem"
    ca_key_path = "crypto/certificates/ca_key.pem"

    # Generate server RSA keys if not already created
    if not os.path.exists(private_key_file) or not os.path.exists(public_key_file):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        with open(private_key_file, "wb") as priv_file:
            priv_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        with open(public_key_file, "wb") as pub_file:
            pub_file.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
        print("Server RSA keys generated and saved.")

    # Check if the CA exists; create if not
    if not os.path.exists(ca_cert_path) or not os.path.exists(ca_key_path):
        ca_key, ca_cert = create_ca()
        save_certificate(ca_cert, ca_cert_path)
        with open(ca_key_path, "wb") as ca_key_file:
            ca_key_file.write(
                ca_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        print("CA created and saved.")

    # Load CA certificate and key
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)

    # Generate server certificate if not already created
    if not os.path.exists(server_cert_path):
        with open(private_key_file, "rb") as priv_file:
            server_private_key = serialization.load_pem_private_key(priv_file.read(), password=None)

        generate_user_certificate("Server", server_private_key, ca_key, ca_cert, cert_filename=server_cert_path)
        print(f"Server certificate generated and saved to {server_cert_path}.")


def start_server():
    ca_cert_path = "crypto/certificates/ca_cert.pem"
    server_cert_path = "crypto/certificates/server_cert.pem"

    if not validate_certificate(server_cert_path, ca_cert_path):
        print("Server certificate validation failed. Exiting...")
        return

    print("Server certificate validated successfully.")
    # Load server's private key for RSA decryption
    with open("server_private.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    # RSA handler with the private key for decryption
    rsa_handler = RSAHandler(public_key=None, private_key=private_key)

    # Server socket setup
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("localhost", 12345))
    server_socket.listen(1)
    print("Server is listening on port 12345...")

    conn, addr = server_socket.accept()
    print(f"Connected to client at {addr}")

    try:
        # Receive data from the client
        data = conn.recv(4096)
        if not data:
            print("No data received from the client.")
            return

        # Split the data: encrypted AES key, encrypted username, encrypted message, and message hash
        # Debugging: Print received data lengths
        print(f"Received data length: {len(data)}")

        # Properly handle splitting using a more robust protocol (e.g., length-prefixed data)
        try:
            encrypted_aes_key, encrypted_username, encrypted_message, received_hash = data.split(b"||")
        except ValueError as e:
            print(f"Data splitting error: {e}")
            return

        print(f"Received encrypted AES key: {encrypted_aes_key}")

        # Decrypt the AES key using RSA private key
        aes_key = rsa_handler.decrypt(encrypted_aes_key)
        if aes_key is None:
            print("Failed to decrypt the AES key.")
            return
        print(f"Decrypted AES Key: {aes_key}")

        # Decrypt the username
        username = rsa_handler.decrypt(encrypted_username).decode()  # Decrypt the username
        print(f"Authenticated User: {username}")

        # Now handle message decryption using AES
        iv = b"RandomIV12345678"  # Predefined IV
        aes_handler = AESHandler(aes_key, iv)

        try:
            # Decrypt the message using AES
            decrypted_message = aes_handler.decrypt(encrypted_message)
            print(f"Decrypted Message: {decrypted_message}")
        except ValueError as e:
            print(f"Error during decryption: {e}")

        # Verify message integrity using SHA-256
        computed_hash = compute_sha256(decrypted_message)
        integrity_check = computed_hash == received_hash.decode()
        print(f"Message Integrity: {'Intact' if integrity_check else 'Compromised'}")

    except Exception as e:
        print(f"Server encountered an error: {e}")
    finally:
        conn.close()
        server_socket.close()
if __name__ == "__main__":
    # Generate keys when the server starts
    create_server_keys()
    start_server()
