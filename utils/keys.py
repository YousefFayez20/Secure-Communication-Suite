from Crypto.Random import get_random_bytes
from secrets import token_bytes
import rsa
def generate_aes_key(key_size=16):
    """Generate a random AES key."""
    return get_random_bytes(key_size)

def generate_iv(block_size=16):
    """Generate a random initialization vector (IV)."""
    return token_bytes(block_size)

def generate_rsa_keys():
    """Generate RSA public and private keys."""
    publickey, privatekey = rsa.newkeys(1024)  # 1024-bit RSA keys
    return publickey, privatekey
