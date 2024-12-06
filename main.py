from utils.keys import generate_aes_key, generate_iv, generate_rsa_keys
from crypto.aes import AESHandler
from crypto.rsaEnDe import RSAHandler
from crypto.hash import compute_sha256, verify_hash

def main():
    # Step 1: Generate AES Key and IV
    aes_key = generate_aes_key()
    iv = generate_iv()

    # Step 2: Generate RSA Keys
    public_key, private_key = generate_rsa_keys()
    rsa_handler = RSAHandler(public_key, private_key)

    # Step 3: Encrypt AES Key using RSA
    rsa_encrypted_aes_key = rsa_handler.encrypt(aes_key)

    # Step 4: Hash the plaintext message
    message = "This is a secure message."
    original_hash = compute_sha256(message)
    print(f"Original SHA-256 Hash: {original_hash}")

    # Step 5: Encrypt Message using AES
    aes_handler = AESHandler(aes_key, iv)
    encrypted_message = aes_handler.encrypt(message)
    print(f"Encrypted Message: {encrypted_message.hex()}")

    # Simulate transmission of encrypted message and hash
    transmitted_data = {
        "ciphertext": encrypted_message,
        "hash": original_hash
    }

    # Step 6: Decrypt AES Key using RSA
    rsa_decrypted_aes_key = rsa_handler.decrypt(rsa_encrypted_aes_key)

    # Step 7: Decrypt Message using AES
    decrypted_message = aes_handler.decrypt(transmitted_data["ciphertext"])
    print(f"Decrypted Message: {decrypted_message}")

    # Step 8: Verify Hash
    is_valid = verify_hash(decrypted_message, transmitted_data["hash"])
    if is_valid:
        print("Integrity Check Passed: Decrypted message matches the original hash.")
    else:
        print("Integrity Check Failed: Message may have been tampered with.")

if __name__ == "__main__":
    main()
