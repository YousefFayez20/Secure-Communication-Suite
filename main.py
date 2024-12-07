from utils.auth import register_user, authenticate_user
from utils.keys import generate_and_store_rsa_keys, load_rsa_keys, generate_aes_key, generate_iv
from crypto.aes import AESHandler
from crypto.hash import compute_sha256, verify_hash
from crypto.signing import sign_message, verify_signature

def main():
    print("=== Secure Communication Suite ===")

    # Step 1: User Registration or Login
    choice = input("1. Register\n2. Login\nChoose an option: ")
    username = input("Enter username: ")
    password = input("Enter password: ")

    if choice == "1":
        register_user(username, password)
        generate_and_store_rsa_keys(username)
    elif choice == "2":
        if not authenticate_user(username, password):
            return
        generate_and_store_rsa_keys(username)

    # Load user keys
    public_key, private_key = load_rsa_keys(username)

    # Step 2: Message Preparation
    message = input("Enter the message to encrypt: ")
    print(f"\nOriginal Message: {message}")

    # Step 3: Hash the message
    message_hash = compute_sha256(message)
    print(f"Message Hash (SHA-256): {message_hash}")

    # Step 4: Sign the message
    signature = sign_message(message, private_key)
    print(f"Message Signature: {signature.hex()}")

    # Step 5: Verify the signature
    is_valid = verify_signature(message, signature, public_key)
    print("Signature Verification:", "Passed" if is_valid else "Failed")

    # Step 6: Encrypt the message using AES
    aes_key = generate_aes_key()
    iv = generate_iv()
    aes_handler = AESHandler(aes_key, iv)
    encrypted_message = aes_handler.encrypt(message)
    print(f"\nEncrypted Message: {encrypted_message.hex()}")

    # Step 7: Decrypt the message
    decrypted_message = aes_handler.decrypt(encrypted_message)
    print(f"Decrypted Message: {decrypted_message}")

    # Verify message integrity
    is_message_intact = verify_hash(decrypted_message, message_hash)
    print("Message Integrity:", "Intact" if is_message_intact else "Compromised")

if __name__ == "__main__":
    main()
