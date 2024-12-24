import os
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime


def create_ca(ca_name="My CA"):
    """Create and return a self-signed CA certificate and private key."""
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"EG"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ca_name),
        x509.NameAttribute(NameOID.COMMON_NAME, ca_name),
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    return ca_key, ca_cert

def save_certificate(cert, cert_path):
    """Save a certificate to a file."""
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(Encoding.PEM))

def load_certificate(cert_path):
    """Load a certificate from a file."""
    if not os.path.exists(cert_path):
        raise FileNotFoundError(f"Certificate file not found: {cert_path}")
    with open(cert_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def validate_certificate(cert_path, ca_cert_path):
    """Validate a certificate against the CA certificate."""
    try:
        cert = load_certificate(cert_path)
        ca_cert = load_certificate(ca_cert_path)

        # Verify the issuer matches the CA's subject
        if cert.issuer != ca_cert.subject:
            raise ValueError("Certificate issuer does not match the trusted CA.")

        print(f"Certificate {cert.subject} is valid.")
        return True
    except Exception as e:
        print(f"Certificate validation failed: {e}")
        return False