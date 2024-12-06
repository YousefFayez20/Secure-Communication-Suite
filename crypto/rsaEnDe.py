import rsa

class RSAHandler:
    def __init__(self, public_key=None, private_key=None):
        self.public_key = public_key
        self.private_key = private_key

    def encrypt(self, data):
        """Encrypt data with RSA public key."""
        return rsa.encrypt(data, self.public_key)

    def decrypt(self, data):
        """Decrypt data with RSA private key."""
        return rsa.decrypt(data, self.private_key)
