import sqlite3
import hashlib


def insert_db(username,password):
    connection= sqlite3.connect("DataBase.db")
    cur=connection.cursor()
    cur.execute("INSERT into Client_Data (USERNAME , PASSSWORD ) values (?,?)",(username,hashlib.sha256(password.encode()).hexdigest()))
#------------------------------------------------------------------------------------------------------------

def Delete_All():
    connection= sqlite3.connect("DataBase.db")
    cur=connection.cursor()
    cur.execute("DELETE FROM Client_Data")
#------------------------------------------------------------------------------------------------------------

def Client_authentication(Username, Password):
    conn = sqlite3.connect("DataBase.db")
    cur = conn.cursor()

    # Hash the provided password before comparing
    hashed_password = hashlib.sha256(Password.encode()).hexdigest()

    cur.execute("SELECT * FROM Client_Data WHERE USERNAME = ? AND PASSSWORD = ?", (Username, hashed_password))
    if cur.fetchall():
        return True
    else:
        return False
#------------------------------------------------------------------------------------------------------------
    
def Client_Registration(client, unique_username):
    client.send("Please Enter a Strong Password".encode())
    New_Password = client.recv(1024).decode()
    New_Password = is_strong(client, New_Password)

    # Hash the password before storing it in the database
    hashed_password = hashlib.sha256(New_Password.encode()).hexdigest()

    add_new_user(unique_username, hashed_password)
    client.send("Congrats, a new Account has been created".encode())
    client.send("Choose Your Command again".encode())
    respond = client.recv(1024).decode()
    return respond

#------------------------------------------------------------------------------------------------------------

def add_new_user(unique_username, hashed_password):
    connection = sqlite3.connect("DataBase.db")
    cur = connection.cursor()
    cur.execute("INSERT INTO Client_Data (USERNAME, PASSSWORD) VALUES (?, ?)", (unique_username, hashed_password))
    connection.commit()
#------------------------------------------------------------------------------------------------------------

def is_strong(client, password):
    while len(password) < 5:
        client.send("Weak password! Please choose a password with 5 or more characters\n".encode())
        password = client.recv(1024).decode()
    return password
#------------------------------------------------------------------------------------------------------------

def is_unique(UserName):
    conn = sqlite3.connect("DataBase.db")
    cur = conn.cursor()

    cur.execute("SELECT * FROM Client_Data WHERE USERNAME = ?", (UserName,))
    if cur.fetchall():
        return True
    else:
        return False
#------------------------------------------------------------------------------------------------------------
  
connection = sqlite3.connect("DataBase.db")
cur = connection.cursor()
cur.execute("""
CREATE TABLE IF NOT EXISTS Client_Data (
            USERNAME VARCHAR(255) PRIMARY KEY,
            PASSSWORD VARCHAR(255) NOT NULL
)
""")
# Delete_All()
# insert_db("admin",hashlib.sha256("admin".encode()).hexdigest())

# password= hashlib.sha256("admin".encode()).hexdigest()

connection.commit()