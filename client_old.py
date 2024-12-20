import socket
import threading
import sys
from colorama import Fore, Style, init
init(convert=True)

from utils.auth import authenticate_user
from utils.keys import generate_aes_key
from crypto.aes import AESHandler
from crypto.hash import compute_sha256
from crypto.rsaEnDe import RSAHandler
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding  # Correct import
from cryptography.hazmat.primitives import hashes

# Function to handle receiving messages from the server
def receive():
    while True:
        try:
            # print("iam in recieve function")
            # Receive messages from the server, decode them from ASCII
            message = client.recv(1024).decode('ascii')
            print(message)
        except:
            # If an error occurs during message reception, print an error message
            # Close the client socket and exit the loop
            client.close()
            break

#------------------------------------------------------------------------------------------------------------

def write():
    while True:
        # print("iam in write function")
        message = f"{input('')}"
        if message.lower() == "/close!":
            client.close()
            sys.exit(0)
        client.send(message.encode('ascii'))
#------------------------------------------------------------------------------------------------------------
def Secure_receive():
    pass
def Secure_write():
    pass


try:
    # Create a socket object
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the server (assuming it's running on '127.0.0.1' at port 56789)
    client.connect(('127.0.0.1', 56789))




# Create a thread for receiving messages and start it

    receive_thread = threading.Thread(target=receive)
    receive_thread.start()

    write_thread = threading.Thread(target=write)
    write_thread.start()

except:
    print("an error Occurred\n")
    print("Maybe their is No server up and running or we lost the connection with the server!\n")