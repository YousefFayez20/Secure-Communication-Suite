from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class RSAHandler:
    def __init__(self, public_key=None, private_key=None):
        self.public_key = public_key
        self.private_key = private_key

    def encrypt(self, data):
        """Encrypt data with RSA public key."""
        ciphertext = self.public_key.encrypt(
            data.encode(),  # Convert to bytes
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    def decrypt(self, data):
        """Decrypt data with RSA private key."""
        try:
            plaintext = self.private_key.decrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return plaintext
        except Exception as e:
            print(f"Decryption failed: {e}")
            return None
    def sign(self, message):
        """Sign a message using the private key."""
        signature = self.private_key.sign(
            message.encode(),  # Convert to bytes
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return signature

    def verify(self, message, signature):
        """Verify the signature of a message using the public key."""
        try:
            self.public_key.verify(
                signature,
                message.encode(),  # Convert to bytes
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            return False
