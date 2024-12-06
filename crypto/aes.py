from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class AESHandler:
    def __init__(self, key, iv):
        self.key = key
        self.iv = iv

    def encrypt(self, plain_text):
        """Encrypts plaintext using AES in CBC mode."""
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        plain_text_padded = pad(plain_text.encode(), AES.block_size)
        cipher_text = cipher.encrypt(plain_text_padded)
        return cipher_text

    def decrypt(self, cipher_text):
        """Decrypts ciphertext using AES in CBC mode."""
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        plain_text_padded = cipher.decrypt(cipher_text)
        plain_text = unpad(plain_text_padded, AES.block_size).decode()
        return plain_text
