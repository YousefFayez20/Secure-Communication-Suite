from utils.keys import generate_aes_key, generate_iv, generate_rsa_keys
from crypto.aes import AESHandler
from crypto.rsaEnDe import RSAHandler

def main():
    # Step 1: Generate AES Key and IV
    aes_key = generate_aes_key()
    iv = generate_iv()

    print(f"Generated AES Key: {aes_key.hex()}")
    print(f"Generated IV: {iv.hex()}")

    # Step 2: Generate RSA Keys (for key exchange)
    public_key, private_key = generate_rsa_keys()
    rsa_handler = RSAHandler(public_key, private_key)

    # Step 3: Encrypt AES Key using RSA
    rsa_encrypted_aes_key = rsa_handler.encrypt(aes_key)
    print(f"Encrypted AES Key using RSA: {rsa_encrypted_aes_key.hex()}")

    # Step 4: Encrypt Message using AES
    aes_handler = AESHandler(aes_key, iv)
    message = "This is a secret message."
    encrypted_message = aes_handler.encrypt(message)
    print(f"Encrypted Message using AES: {encrypted_message.hex()}")

    # Step 5: Decrypt AES Key using RSA
    rsa_decrypted_aes_key = rsa_handler.decrypt(rsa_encrypted_aes_key)
    print(f"Decrypted AES Key using RSA: {rsa_decrypted_aes_key.hex()}")

    # Step 6: Decrypt Message using AES
    decrypted_message = aes_handler.decrypt(encrypted_message)
    print(f"Decrypted Message using AES: {decrypted_message}")

if __name__ == "__main__":
    main()
