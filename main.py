from utils.auth import register_user, authenticate_user, generate_user_certificate, get_registered_users
from utils.keys import generate_rsa_keys, generate_aes_key, generate_iv
from crypto.aes import AESHandler
from crypto.hash import compute_sha256, verify_hash
from crypto.ca import create_ca
from crypto.rsaEnDe import RSAHandler


def main():
    print("=== Secure Communication Suite ===")
    print("1. Register User")
    print("2. Login and Use Suite")
    print("3. View Registered Users")
    choice = input("Choose an option: ").strip()

    if choice == "1":
        # Registration
        username = input("Enter a username: ").strip()
        password = input("Enter a password: ").strip()

        # Register user and generate RSA keys
        register_user(username, password)
        public_key, private_key = generate_rsa_keys()

        # Generate certificate
        ca_key, ca_cert = create_ca()
        generate_user_certificate(username, private_key, ca_key, ca_cert)
        print(f"User {username} registered successfully!")

    elif choice == "2":
        # Login
        username = input("Enter your username: ").strip()
        password = input("Enter your password: ").strip()

        if not authenticate_user(username, password):
            print("Login failed.")
            return

        print(f"Welcome back, {username}!")

        # Generate or retrieve RSA keys
        public_key, private_key = generate_rsa_keys()

        # Symmetric Encryption with AES
        message = input("Enter a message to secure: ").strip()
        aes_key = generate_aes_key()
        iv = generate_iv()
        aes_handler = AESHandler(aes_key, iv)
        encrypted_message = aes_handler.encrypt(message)
        print(f"\nEncrypted Message (AES): {encrypted_message.hex()}")

        # Hashing for Integrity
        message_hash = compute_sha256(message)
        print(f"Message Hash (SHA-256): {message_hash}")

        # Sign the Message with RSA
        rsa_handler = RSAHandler(public_key, private_key)
        signature = rsa_handler.sign(message)
        print(f"Message Signature: {signature.hex()}")

        # Verify Signature
        is_signature_valid = rsa_handler.verify(message, signature)
        print(f"Signature Verification: {'Passed' if is_signature_valid else 'Failed'}")

        # Decrypt AES Message
        decrypted_message = aes_handler.decrypt(encrypted_message)
        print(f"Decrypted Message: {decrypted_message}")

        # Verify Integrity
        is_message_intact = verify_hash(decrypted_message, message_hash)
        print(f"Message Integrity: {'Intact' if is_message_intact else 'Compromised'}")

    elif choice == "3":
        # Display Registered Users
        print("\nRegistered Users:")
        users = get_registered_users()
        if users:
            for user in users:
                print(f"- {user}")
        else:
            print("No users registered.")

    else:
        print("Invalid option. Exiting.")


if __name__ == "__main__":
    main()