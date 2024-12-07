import hashlib
import os

def register_user(username, password):
    """Register a new user by storing hashed password."""
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    with open("data/auth.txt", "a") as f:
        f.write(f"{username},{hashed_password}\n")
    print(f"User {username} registered successfully!")

def authenticate_user(username, password):
    """Authenticate user by validating username and hashed password."""
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    with open("data/auth.txt", "r") as f:
        for line in f:
            stored_username, stored_hash = line.strip().split(",")
            if stored_username == username and stored_hash == hashed_password:
                print(f"User {username} authenticated successfully!")
                return True
    print("Authentication failed. Invalid username or password.")
    return False
