import socket

from cryptography.hazmat.primitives.asymmetric import rsa

from utils.keys import generate_rsa_keys
from crypto.aes import AESHandler
from crypto.hash import compute_sha256
from crypto.rsaEnDe import RSAHandler
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding



private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
print(private_key)
private_key = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption())

print(private_key)

print("----------------")
print("----------------")


with open("server_private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)
    print(private_key)
