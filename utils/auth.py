import hashlib
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import CertificateSigningRequestBuilder, CertificateBuilder
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption
import datetime

def register_user(username, password):
    """Register a new user by storing hashed password."""
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    with open("data/auth.txt", "a") as f:
        f.write(f"{username},{hashed_password}\n")
    print(f"User {username} registered successfully!")

def authenticate_user(username, password):
    """Authenticate user by validating username and hashed password."""
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    with open("data/auth.txt", "r") as f:
        for line in f:
            stored_username, stored_hash = line.strip().split(",")
            if stored_username == username and stored_hash == hashed_password:
                print(f"User {username} authenticated successfully!")
                return True
    print("Authentication failed. Invalid username or password.")
    return False

def generate_user_certificate(username, user_private_key, ca_key, ca_cert):
    """Generate a user certificate signed by the CA."""
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
    cert_path = f"crypto/certificates/{username}.crt"
    with open(cert_path, "wb") as cert_file:
        cert_file.write(user_cert.public_bytes(Encoding.PEM))
    print(f"Certificate for {username} saved at {cert_path}.")
