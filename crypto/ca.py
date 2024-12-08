from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
import datetime
import os

def create_ca():
    """Create a self-signed CA certificate."""
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Organization"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"My CA"),
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
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    # Save CA key and certificate
    os.makedirs("crypto/certificates", exist_ok=True)
    with open("crypto/certificates/ca_key.pem", "wb") as key_file:
        key_file.write(ca_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        ))
    with open("crypto/certificates/ca_cert.pem", "wb") as cert_file:
        cert_file.write(ca_cert.public_bytes(Encoding.PEM))

    return ca_key, ca_cert
