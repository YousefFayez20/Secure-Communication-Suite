import socket

from cryptography.hazmat.primitives.asymmetric import rsa

from utils.keys import generate_rsa_keys
from crypto.aes import AESHandler
from crypto.hash import compute_sha256
from crypto.rsaEnDe import RSAHandler
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding

def create_server_keys():
    """Generate server's RSA key pair and save the public key."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Save the private key (optional, for server-side use only)
    with open("server_private.pem", "wb") as priv_file:
        priv_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Extract and save the public key
    public_key = private_key.public_key()
    with open("server_public.pem", "wb") as pub_file:
        pub_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    print("Server RSA keys generated and saved to server_public.pem and server_private.pem.")


def start_server():
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
        while True:
            # Receive data from the client
            data = conn.recv(4096)
            if not data:
                print("No data received from the client.")
                continue
                # return

            # Split the data: encrypted AES key, encrypted username, encrypted message, and message hash
            encrypted_aes_key, encrypted_username, encrypted_message, received_hash = data.split(b"||")
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

            decrypted_message = aes_handler.decrypt(encrypted_message)
            print(f"Decrypted Message: {decrypted_message}")

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
