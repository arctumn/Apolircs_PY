from ssl import SSLSocket
from client import client
import sqlite3
from sqlite3 import Error

# login.__.username.__.passwd_hash
# register.__.username.__.passwd_hash.__.passwd_salt
# globalMSG.__.a.__.a.__.a.__.a.__.a.__.a.__.
# privateMSG.__.a.__.a.__.a.__.a.__.a.__.a.__.

#CREATE TABLE user(id INTEGER PRIMARY KEY,
#nome varchar(32) not null UNIQUE,
#passHash varchar(32) not null UNIQUE,
#passSalt varchar(32) not null,
#socketIP varchar(32) not null,
#PKEYENCRYPT varchar(64) not null UNIQUE,
#PKEYSIGN varchar(64) not null UNIQUE );

#insert into user (
#nome,passHash,passSalt,socketIP,PKEYENCRYPT,PKEYSIGN
# ) values (
#'admin','3124asd1d24dqwe','ddwqdfqwe1234','0.0.0.0','............','...........'
#);
#1|admin|3124asd1d24dqwe|ddwqdfqwe1234|0.0.0.0|............|...........

def create_connection(db_file):
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        #print(sqlite3.version)
    except Error as e:
        print(e)
    finally:
        if conn:
            conn.close()

def get_salt(username:str,client_socket:SSLSocket) -> None:
    conn = sqlite3.connect("Users.db")
    cursor = conn.cursor()
    #print(username)
    try:
        cursor.execute(f"select passSalt from user where (nome = '{username}');")

        row = cursor.fetchall()[0]

        if row:
                out:str = row[0]
                #print(out)
                client_socket.send(out.encode())
                conn.close()
                return
            #return client_found
        #print("FAILURE")
    except Error as e:
        print(e.args)
        client_socket.send(f"ERRO A DAR LOGIN {e.args}".encode('utf-8'))

def create_user_db(message:str,client_socket:SSLSocket):
    try:
        conn = sqlite3.connect("Users.db")
        
        _,username,passwd_hash,passwd_salt = message.split(".__.")
       
        gen_client = client(username,passwd_hash,passwd_salt,client_socket)

        gen_client.send_to_owner()
       
    
     
        conn.execute(f'insert into user(nome,passHash,passSalt,socketIP,PKEYENCRYPT,PKEYSIGN) values (\'{gen_client.name}\',\'{gen_client.passwd_hash}\',\'{gen_client.passwd_salt}\',\'{gen_client.socket_info.getsockname()[0]}\',{str(gen_client.encrypt_mesages[1]).removeprefix("b")},{str(gen_client.sign_mesages[1]).removeprefix("b")});')
       
        conn.commit()
    except Error as e:
        print(f"ERRO NA DB {e.args}")
        client_socket.close()
    conn.close()
    


def login_client(message:str,client_socket:SSLSocket) -> client:
    _,username,passwd = message.split(".__.")
    conn = sqlite3.connect("Users.db")
    cursor = conn.cursor()
    try:
        cursor.execute(f"select * from user where (nome = '{username}' and passHash = '{passwd}');")
        
        row = cursor.fetchall()[0]
        if row:
                        
            client_found = client(row[1],row[2],row[3],client_socket,create_new=False)
            client_found.encrypt_mesages = (None,row[5])
            client_found.sign_mesages = (None,row[6])
            client_socket.send("Online".encode())
            conn.close()
            return client_found

    except Error as e:
        client_socket.send(f"ERRO A DAR LOGIN {e.args}".encode('utf-8'))
        
def get_client(user:str,client_socket:SSLSocket) -> client:
    conn = sqlite3.connect("Users.db")
    cursor = conn.cursor()
    try:
        row = cursor.execute(f"select * from user where (nome = '{user}');")
        
        row = cursor.fetchall()[0]
        if row:

            client_found = client(row[1],row[2],row[3],client_socket,create_new=False)
            client_found.encrypt_mesages = (None,row[5])
            client_found.sign_mesages = (None,row[6])
            
            conn.close()
            return client_found

    except Error as e:
        client_socket.send(f"ERRO A DAR LOGIN {e.args}".encode('utf-8'))