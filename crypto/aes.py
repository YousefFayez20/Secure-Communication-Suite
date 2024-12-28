from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


#and used over DES because AES key size is 128 bits, which makes it stronger against brute force attacks unlike DES which have a key size of 56 bit 
class AESHandler:
    def __init__(self, key, iv):
        self.key = key
        self.iv = iv
        self.cipher = AES.new(self.key, AES.MODE_CBC, self.iv)

    def encrypt(self, plain_text):
        """Encrypts plaintext using AES in CBC mode .a 16-byte (128-bit) key is used  """
        plain_text_padded = pad(plain_text.encode(), AES.block_size)
        cipher_text = self.cipher.encrypt(plain_text_padded)
        return cipher_text

    def decrypt(self, cipher_text):
        """Decrypts ciphertext using AES in CBC mode."""
        plain_text_padded = self.cipher.decrypt(cipher_text)
        plain_text = unpad(plain_text_padded, AES.block_size).decode()
        return plain_text
