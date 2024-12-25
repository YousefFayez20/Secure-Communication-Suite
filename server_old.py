import socket
import threading
import hashlib
import sqlite3
import sys
import colorama

from utils.auth import authenticate_user
from utils.keys import generate_aes_key
from crypto.aes import AESHandler
from crypto.hash import compute_sha256
from crypto.rsaEnDe import RSAHandler
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding  # Correct import
from cryptography.hazmat.primitives import hashes

from Database import Client_authentication, Client_Registration, is_unique
import time
from colorama import Fore, Style, init

init(convert=True)
host = '127.0.0.1'
port = 56789

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen()

chat_rooms = {}
clients = {}
one_to_one = {}
clients_keys = {}


def create_chat_room(client):
    # send client a prompt to enter name of new chat room
    client.send("Enter the name of the new chat room:\n ".encode())
    # response from client
    room_name = client.recv(1024).decode()

    # check that chat room doesn't already exist.
    if room_name not in chat_rooms:
        # update list of clients in chat room
        chat_rooms[room_name] = [client]
        client.send(f"Chat room '{room_name}' created!\n".encode())
        client.send(f"Type [/exit] if you want to exit the chat room!\n".encode())

        while True:
            # receive message from a user in chat room
            chat_message = client.recv(1024).decode()

            # if received message is the exist flag, user will exit the chatroom and will be removed from the chat room.
            if chat_message == '/exit':
                client.send(f"You exited chatroom: {room_name}".encode())
                broadcast_chatroom(client, f"exited the chat room!\n", room_name)
                # remove client from the list after he exits the chat room.
                chat_rooms[room_name].remove(client)

                delete_chatroom(room_name)
                break
            else:
                broadcast_chatroom(client, f"{chat_message}", room_name)
    else:
        client.send(f"Chat room '{room_name}' already exists. Choose a different name.\n".encode())

# ------------------------------------------------------------------------------------------------------------#

def is_online(client, respond):
    flag = False
    username = None
    client2 = None
    for key in clients:

        if clients[key][0] == respond:
            flag = True
            username = clients[key][0]
            client2 = key
            one_to_one[client] = client2
            client.send(f"Waiting for [{username}'s] to enter 1-to-1 chatting room...\n".encode())
            client2.send(f"CHAT REQUEST 1-TO-1! FROM [{clients[client][0]}]\n".encode())
            client2.send(f"GO to menue and choose one-to-one chat to chat with him\n".encode())
            client2.send(f"You have 30 seconds to respond otherwise you will not catch him\n".encode())
            return username, flag, client2

    return username, flag, client2


# ------------------------------------------------------------------------------------------------------------#
def one_2_one_chat(client, client2):
    # Clear the screen for both clients
    client.send("\033c".encode())
    client2.send("\033c".encode())
    message = "--------one-to-one initiated with [" + Fore.GREEN + f"{clients[client2][0]}" + Style.RESET_ALL + "]--------\n"
    client.send(message.encode())
    message = "--------one-to-one initiated with [" + Fore.GREEN + f"{clients[client][0]}" + Style.RESET_ALL + "]--------\n"
    client2.send(message.encode())
    message = f"You can exit at any time by typing" + Fore.RED + " /exit" + Style.RESET_ALL + "\n"
    client.send(message.encode())
    message = f"You can exit at any time by typing" + Fore.RED + " /exit" + Style.RESET_ALL + "\n"
    client2.send(message.encode())


    while True and (client in one_to_one) and (client2 in one_to_one):
        try:
            chat_message = client.recv(1024).decode()
            if chat_message == '/exit':
                if client2 in one_to_one and client in one_to_one:
                    del one_to_one[client]
                    del one_to_one[client2]
                return
            else:
                if client2 in one_to_one and client in one_to_one:
                    message = Fore.MAGENTA + f"{clients[client][0]}" + Style.RESET_ALL + f": {chat_message}"
                    client2.send(message.encode())
        except ConnectionResetError:
            # Handle client disconnection gracefully
            if client2 in one_to_one and client in one_to_one:
                del one_to_one[client]
                del one_to_one[client2]
            return
        except OSError as e:
            # Handle OS error (WinError 10038)
            print(f"Error: {e}")
            if client2 in one_to_one and client in one_to_one:
                del one_to_one[client]
                del one_to_one[client2]

            return


# ------------------------------------------------------------------------------------------------------------#
def one_to_one_request(client):
    while True:
        try:
            message = (Fore.YELLOW + "Please enter the Name of an online client you want to chat with or '" +
                       Style.RESET_ALL + Fore.RED + "/exit" + Style.RESET_ALL + Fore.YELLOW + "' to return to menu\n")
            client.send(message.encode())
            respond = client.recv(1024).decode()

            # check if this nickname exists in the database or not
            does_exist = is_unique(respond)
            # user is in the database
            if does_exist:
                nickname, flag, client2 = is_online(client, respond)
                # user is not online
                if flag is False:
                    message = Fore.RED + "User is not online!\n" + Style.RESET_ALL
                    client.send(message.encode())
                    continue
                # user is online
                else:
                    count = 30
                    client.send("Remaining Time:\n".encode())
                    while count:
                        client.send(f"{count}\t".encode())
                        count -= 1
                        time.sleep(1)
                        if ((one_to_one[client] == client2) and (client2 in one_to_one)):
                            if one_to_one[client2] == client:
                                one_2_one_chat(client, client2)
                                return
                    if count == 0:
                        message = Fore.RED + "Invitation has expired!\n" + Style.RESET_ALL
                        client.send(message.encode())
                        del one_to_one[client]

            elif respond == "/exit":
                return
            else:
                client.send("This nickname does not exist\n".encode())
        except ConnectionResetError:
            # Handle client disconnection gracefully
            if client in clients:
                print(f"Client {clients[client][0]} disconnected from the chat.")
            if client in one_to_one:
                del one_to_one[client]
            return


# ------------------------------------------------------------------------------------------------------------#


def join_chat_room(client, room_name):
    # if no room name is passed as an argument the user is asked to provide the room name.
    if room_name == '':
        message = Fore.YELLOW + "Enter the name of the chat room you want to join: \n" + Style.RESET_ALL
        client.send(message.encode())
        room_name = client.recv(1024).decode()

    # room is check to already exist.
    if room_name in chat_rooms:
        # client is appended to the members list
        chat_rooms[room_name].append(client)
        message = "Type [" + Fore.RED + "/exit" + Style.RESET_ALL + "] if you want to exit the chat room at any Time!\n"
        client.send(message.encode())
        client.send(f"Happy Chatting :)\n".encode())

        broadcast_chatroom(client, f"has joined the chat!\n", room_name)  # loon a5dar

        while True:
            chat_message = client.recv(1024).decode()

            if chat_message == '/exit':
                message = "You exited the chatroom " + Fore.RED + f"{room_name}" + Style.RESET_ALL
                client.send(message.encode())
                broadcast_chatroom(client, f"has exited the chat room!\n", room_name)  # loon a7mar
                chat_rooms[room_name].remove(client)
                delete_chatroom(room_name)
                break
            else:
                broadcast_chatroom(client, f"{chat_message}", room_name)
    else:
        message = "Chat room " + Fore.RED + f"{room_name}" + Style.RESET_ALL + " does not exist. Create the room or choose another.\n"
        client.send(message.encode())


# ------------------------------------------------------------------------------------------------------------
def show_available_chat_rooms(client):
    # checking if the chat Room dictionary is empty or not
    if len(chat_rooms):
        client.send("Available Chat Rooms:\n".encode())
        # print list of all chat rooms
        for room in chat_rooms:
            message = Fore.GREEN + f"{room}" + Style.RESET_ALL + "\n"
            client.send(message.encode())

        # user is prompted to enter a chat room in list. (if desired)
        message = (Fore.YELLOW + "Enter the name of the Chat Room you want to join or type [" + Style.RESET_ALL
        + Fore.RED + "/back" + Style.RESET_ALL + Fore.YELLOW + "] to go back: \n" + Style.RESET_ALL)
        client.send(message.encode())
        room_choice = client.recv(1024).decode()
        while True:

            if room_choice == '/back':
                return
            elif room_choice in chat_rooms:
                join_chat_room(client, room_choice)
                # dont forget that I will return from the "join_chat_room" fucntion if the client exited from the function
                return
            else:
                message = Fore.RED + "Invalid chat room choice. OR invalid Command.\n" + Style.RESET_ALL
                client.send(message.encode())
                message = (Fore.YELLOW + "Enter the name of the chat room you want to join or type [" + Style.RESET_ALL + Fore.GREEN + "/back"
                + Style.RESET_ALL + Fore.YELLOW + "] to go back:\n" + Style.RESET_ALL)
                client.send(message.encode())
                room_choice = client.recv(1024).decode()

    else:  # in case there is no chat Rooms
        message = Fore.RED + "There is No Available chat Rooms :( \n" + Style.RESET_ALL
        client.send(message.encode())
        message = Fore.YELLOW + "Type [" + Style.RESET_ALL + Fore.RED + "/back" + Style.RESET_ALL + Fore.YELLOW + "] to go back\n" + Style.RESET_ALL
        client.send("Type [/back] to go back\n".encode())
        respond = client.recv(1024).decode()
        while True:
            if respond == "/back":
                return
            else:
                message = Fore.RED + "Invalid Command,Please Enter A valid command\n" + Style.RESET_ALL
                client.send(message.encode())
                respond = client.recv(1024).decode()


# ------------------------------------------------------------------------------------------------------------
# Delete a chatroom
def delete_chatroom(room_name):
    # chatroom is deleted if number of members reaches zero.
    if room_name in chat_rooms and len(chat_rooms[room_name]) == 0:
        del chat_rooms[room_name]
        message = "Chat room" + Fore.RED + f'{room_name}' + Style.RESET_ALL + " has been deleted!\n"
        print(message)


# ------------------------------------------------------------------------------------------------------------
def change_nickname(client, nickname):
    # send a prompt to the client to enter his new nickname
    message = Fore.YELLOW + "Enter new nickname: \n" + Style.RESET_ALL
    client.send(message.encode())
    # received response from the client
    new_nickname = client.recv(1024).decode()
    # updated the client's nickname
    clients[client][1] = new_nickname
    # printed the new nickname in the server log
    message = "Nickname of the client " + Fore.YELLOW + f'{nickname}' + Style.RESET_ALL + " is now changed to " + Fore.GREEN + f'{new_nickname}' + Style.RESET_ALL
    print(message)
    # notified all clients of the new nickname
    message = Fore.YELLOW + f'{nickname}' + Style.RESET_ALL + " is now called " + Fore.GREEN + f'{new_nickname}' + Style.RESET_ALL
    broadcast(message)
    # notified the client that his nickname has been successfully updated
    message = "Nickname successfully changed to " + Fore.YELLOW + f'{new_nickname}' + Style.RESET_ALL + " !\n"
    client.send(message.encode('ascii'))
    return
# ------------------------------------------------------------------------------------------------------------
# def close_app():  #!!!!!!!! add if statement to to remove if existed client in list
#     # if a user enters "close!" the flag 'exit flag' is sent to client-side.
#     try:
#         client.send("exit flag".encode())
#         # Client connection terminates.
#         client.close()
#         sys.exit(0)
#     except:
#         pass
# ------------------------------------------------------------------------------------------------------------
def Logout(client):
    # Broadcast the user's logout to other clients
    message = Fore.RED + f'{clients[client][1]}' + Style.RESET_ALL + " is now offline!\n"
    broadcast(message)
    # Update server log
    message = "User " + Fore.RED + f"{clients[client][0]}" + Style.RESET_ALL + " logged out.\n"
    print(message)

    # Remove the client from the clients dictionary
    del clients[client]
# ------------------------------------------------------------------------------------------------------------
def Show_Menue(client):
    while True:

        # client.send(str(Fore.WHITE+"Welcome To the Local P2P Chatting Application\n").encode())
        client.send(f"Welcome '{clients[client][1]}'To the Local P2P Chatting Application\n".encode())
        message = "1- Press [" + Fore.YELLOW + "1" + Style.RESET_ALL + "] To " + Fore.GREEN + "See Online Users\n" + Style.RESET_ALL
        client.send(message.encode())
        message = "2- Press [" + Fore.YELLOW + "2" + Style.RESET_ALL + "] To " + Fore.GREEN + "create Chat Room\n" + Style.RESET_ALL
        client.send(message.encode())
        message = "3- Press [" + Fore.YELLOW + "3" + Style.RESET_ALL + "] To " + Fore.GREEN + "Join Chat Room\n" + Style.RESET_ALL
        client.send(message.encode())
        message = "4- Press [" + Fore.YELLOW + "4" + Style.RESET_ALL + "] To " + Fore.GREEN + "see Available ChatRooms\n" + Style.RESET_ALL
        client.send(message.encode())
        message = "5- Press [" + Fore.YELLOW + "5" + Style.RESET_ALL + "] To " + Fore.GREEN + "initiate one-to-one chatting Room\n" + Style.RESET_ALL
        client.send(message.encode())
        message = "6- Press [" + Fore.YELLOW + "6" + Style.RESET_ALL + "] To " + Fore.GREEN + "Change your Nickname\n" +Style.RESET_ALL
        client.send(message.encode())
        message = "7- Press [" + Fore.YELLOW + "7" + Style.RESET_ALL + "] To " + Fore.RED + "logout\n" + Style.RESET_ALL
        client.send(message.encode())
        message = "8- Press [" + Fore.YELLOW + "8" + Style.RESET_ALL + "] at any time To " + Fore.RED + "Close The application\n" + Style.RESET_ALL
        client.send(message.encode())

        Respond = client.recv(1024).decode()

        if Respond == '1':
            show_Online(client)
        elif Respond == '2':
            create_chat_room(client)
        elif Respond == '3':
            join_chat_room(client, room_name='')
        elif Respond == '4':
            show_available_chat_rooms(client)
        elif Respond == '5':
            one_to_one_request(client)
        elif Respond == '6':
            change_nickname(client, clients[client][1])
        elif Respond == '7':
            Logout(client)
            break
        else:
            client.send("Invalid command Please enter a valid command\n".encode())
# ------------------------------------------------------------------------------------------------------------
def show_Online(client):
    client.send("Online Users:\n".encode())
    for key in clients:
        message = Fore.CYAN + f"{clients[key][0]}" + Style.RESET_ALL + " AKA '" + Fore.GREEN + f"{clients[key][1]}" + Style.RESET_ALL
        client.send(message.encode())
    message = "\n1-Enter [" + Fore.YELLOW + "R" + Style.RESET_ALL + "] to" + Fore.GREEN + " return to the Menu" + Style.RESET_ALL
    client.send(message.encode())
    message = "\n2-Enter [" + Fore.RED + "/Close!" + Style.RESET_ALL + "] to" + Fore.GREEN + " Close the Application" + Style.RESET_ALL
    client.send(message.encode())

    Respond = client.recv(1024).decode()
    while True:

        if Respond.lower() == 'r':
            return
        elif Respond.lower() == 'Close!':
            pass
        else:
            message = Fore.RED + "Please enter a valid command!\n" + Style.RESET_ALL
            client.send(message.encode())
            Respond = client.recv(1024).decode()

# ------------------------------------------------------------------------------------------------------------
# !!!!!!!!!! handle same login username
def Login_or_register(client):
    # client.send(str(Fore.WHITE+"Welcome To the Local P2P Chatting Application\n").encode())
    client.send("Welcome To the Local P2P Chatting Application\n".encode())
    message = "1- Enter [" + Fore.GREEN + "login" + Style.RESET_ALL + "] to login\n"
    client.send(message.encode())
    message = "2- Enter [" + Fore.YELLOW + "Register" + Style.RESET_ALL + "] if You are New!\n"
    client.send(message.encode())
    message = "3- Type [" + Fore.RED + "/Close!" + Style.RESET_ALL + "] if You want to leave the chatting application\n"
    client.send(message.encode())
    respond = client.recv(1024).decode()

    while True:
        if respond.lower() == "login":
            message = Fore.YELLOW + "Username :" + Style.RESET_ALL
            client.send(message.encode())
            Username = client.recv(1024).decode()

            # Check if the username is already logged in
            if any(Username == clients[c][0] for c in clients):
                message = Fore.RED + "This user is already logged in. Choose a different command or username.\n" + Style.RESET_ALL
                client.send(message.encode())
                continue

            message = Fore.YELLOW + "Password :" + Style.RESET_ALL
            client.send(message.encode())
            Password = client.recv(1024).decode()  # Receive the password directly

            status = Client_authentication(Username, Password)

            if status:
                message = Fore.GREEN + "Login Successful !" + Style.RESET_ALL
                client.send(message.encode())
                # usernames.append({Username:None})
                return Username
            else:
                message = Fore.RED + "Wrong UserName or Password!\n" + Style.RESET_ALL
                client.send(message.encode())
                client.send("Choose Your Command again\n".encode())
                respond = client.recv(1024).decode()

        elif respond.lower() == "register":
            message = Fore.YELLOW + "Please enter a Unique Username\n" + Style.RESET_ALL
            client.send(message.encode())
            unique_username = client.recv(1024).decode()
            status = is_unique(unique_username)

            if status:
                message = Fore.RED + "This Username Has been Taken.\n" + Style.RESET_ALL
                client.send(message.encode())
            else:
                respond = Client_Registration(client, unique_username)

        # elif respond.lower() == "/close!":
        #     close_app()

        else:
            message = Fore.RED + "Please enter A valid Command !\n" + Style.RESET_ALL
            client.send(message.encode())
            respond = client.recv(1024).decode()

# ------------------------------------------------------------------------------------------------------------
def broadcast(message):
    # Create a list of clients to remove
    to_remove = []
    for client in clients:
        try:
            # Try to send the message to the client
            client.send(message.encode())
        except ConnectionResetError:
            # Handle client disconnection gracefully
            message = f"Client " + Fore.RED + f"{clients[client][0]}" + Style.RESET_ALL + " disconnected from the chat!"
            print(message)
            to_remove.append(client)

    # Remove disconnected clients from the clients dictionary
    for client in to_remove:
        del clients[client]
# ------------------------------------------------------------------------------------------------------------
# Broadcasts a message to all members of a specific chat room.
def broadcast_chatroom(client, message, room_name):
    if room_name in chat_rooms:
        for c in chat_rooms[room_name]:
            if c == client:
                continue
            else:
                message_c = Fore.CYAN + f"{clients[client][1]}" + Style.RESET_ALL + f": {message}"
                c.send(message_c.encode())
# ------------------------------------------------------------------------------------------------------------
# def handle(client):
#     while True:
#         try:
#             message = client.recv(1024)
#             broadcast(message)

#         except:

#             print(f"Lost connection with {clients[client][1]}")
#             broadcast(f'{clients[client][1]} is now offline!'.encode())

#             client.close()
#             del clients[client]
#             break
# ------------------------------------------------------------------------------------------------------------

def Handle_Client(client, address):
    try:
        while True:
            try:
                Username = Login_or_register(client)
                message = "Connected with " + Fore.GREEN + f"{str(address)}" + Style.RESET_ALL
                print(message)
                message = Fore.YELLOW + "Choose your Nickname :\n" + Style.RESET_ALL
                client.send(message.encode('ascii'))
                nickname = client.recv(1024).decode('ascii')
                clients[client] = [Username, nickname]
                
                # intialize the keys here

                message = "Nickname of the client is " + Fore.GREEN + f"{nickname}" + Style.RESET_ALL
                print(message)
                message = Fore.YELLOW + f"{Username}" + Style.RESET_ALL + " is now online as " + Fore.GREEN + f"{nickname}" + Style.RESET_ALL
                broadcast(message)
                message = Fore.GREEN + "Connected to the server!\n" + Style.RESET_ALL
                client.send(message.encode('ascii'))

                Show_Menue(client)
            except ConnectionResetError:
                message = "Lost connection with " + Fore.RED + f"{str(address)}" + Style.RESET_ALL
                print(message)
                # client may get disconnected before saving or appending his data (login)
                if client in clients:
                    message = Fore.RED + f"{clients[client][0]}" + Style.RESET_ALL + " is now offline!"
                    broadcast(message)
                    client.close()
                    del clients[client]
                    break
                else:
                    client.close()
                    break
    except KeyError:
        pass


# ------------------------------------------------------------------------------------------------------------

print("Server is listening...")

while True:
    client, address = server.accept()
    threading.Thread(target=Handle_Client, args=(client, address)).start()