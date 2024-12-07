from Crypto.Random import get_random_bytes
from secrets import token_bytes
import rsa
import os
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

def generate_and_store_rsa_keys(username):
    """Generate RSA keys and store them in the user's directory."""
    private_key_file = f"data/keys/{username}_private.pem"
    public_key_file = f"data/keys/{username}_public.pem"

    if not (os.path.isfile(private_key_file) and os.path.isfile(public_key_file)):
        public_key, private_key = rsa.newkeys(1024)
        with open(private_key_file, "wb") as f:
            f.write(private_key.save_pkcs1("PEM"))
        with open(public_key_file, "wb") as f:
            f.write(public_key.save_pkcs1("PEM"))
        print(f"RSA keys generated for {username}.")
    else:
        print(f"RSA keys for {username} already exist.")

def load_rsa_keys(username):
    """Load RSA keys for the given user."""
    private_key_file = f"data/keys/{username}_private.pem"
    public_key_file = f"data/keys/{username}_public.pem"

    with open(private_key_file, "rb") as f:
        private_key = rsa.PrivateKey.load_pkcs1(f.read())
    with open(public_key_file, "rb") as f:
        public_key = rsa.PublicKey.load_pkcs1(f.read())
    return public_key, private_key
