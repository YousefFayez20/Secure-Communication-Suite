import rsa

def sign_message(message, private_key):
    """Sign a message using the user's private key."""
    signature = rsa.sign(message.encode(), private_key, "SHA-256")
    return signature

def verify_signature(message, signature, public_key):
    """Verify the signature of a message using the sender's public key."""
    try:
        rsa.verify(message.encode(), signature, public_key)
        return True
    except rsa.VerificationError:
        return False
