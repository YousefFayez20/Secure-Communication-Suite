import hashlib
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import CertificateSigningRequestBuilder, CertificateBuilder
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption
import datetime
AUTH_FILE = "data/auth.txt"
USERS_FILE = "data/users.txt"
def register_user(username, password):
    """Register a new user by storing hashed password and username."""
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    os.makedirs("data", exist_ok=True)

    # Store username and hashed password in auth file
    with open(AUTH_FILE, "a") as f:
        f.write(f"{username},{hashed_password}\n")

    # Add username to users file
    with open(USERS_FILE, "a") as f:
        f.write(f"{username}\n")

    print(f"User {username} registered successfully!")
def authenticate_user(username, password):
    """Authenticate user by validating username and hashed password."""
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    with open(AUTH_FILE, "r") as f:
        for line in f:
            stored_username, stored_hash = line.strip().split(",")
            if stored_username == username and stored_hash == hashed_password:
                print(f"User {username} authenticated successfully!")
                return True
    print("Authentication failed. Invalid username or password.")
    return False

def get_registered_users():
    """Retrieve the list of registered users."""
    if not os.path.isfile(USERS_FILE):
        print("No registered users found.")
        return []
    with open(USERS_FILE, "r") as f:
        users = [line.strip() for line in f]
    return users
def generate_user_certificate(username, user_private_key, ca_key, ca_cert, cert_filename=None):
    """Generate a user certificate signed by the CA."""
    if not cert_filename:
        cert_filename = f"crypto/certificates/{username}.crt"

    # Create CSR using the user's private key
    csr = (
        CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, username),
        ]))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key=user_private_key, algorithm=hashes.SHA256())
    )

    # Sign the CSR with the CA's private key
    user_cert = (
        CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(user_private_key.public_key())  # Use the public key
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    # Save user certificate
    with open(cert_filename, "wb") as cert_file:
        cert_file.write(user_cert.public_bytes(Encoding.PEM))
    print(f"Certificate for {username} saved at {cert_filename}.")
