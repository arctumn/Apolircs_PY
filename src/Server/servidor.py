import ssl
import threading
import socket
from client import client
from database import *
from private_message import *
from sys import argv

#import functools as fun
#import asyncio
host = '192.168.2.26'
port = 4004

clients = []
online_client_sockets = [SSLSocket]

def broadcast(client_sender:client,message:str) -> None:
    try:    
        message_with_sign = message +  ".__." + client_sender.sign_key()
        #print(message_with_sign)
        for cliente in clients:
            if cliente.name != client_sender.name:
                cliente.send_message(("globalMSG"+client_sender.name + " -> " + message_with_sign).encode())
    except Exception as e:
        print(e.args)
# Function to handle clients'connections
def handle_client(client:SSLSocket) -> None:
    while True:
        try:
            message = client.recv(1024).decode()
            if parseInput(message,client):
                raise Exception("Fim de conversa")
        except Exception as e:
            print(e.args)
            for client_inside in clients:
                if client_inside.socket_info == client:
                    clients.remove(client_inside)
                    break
            client.close()
            #print(list(map(lambda x : "nome->: "+ x.name ,clients)))
            
            break



def parseInput(message:str,client_socket:SSLSocket) -> bool:
    try:
        client_user:client = None
        #print(f"conteudo: {message}")
        if message.find("register") != -1:
            #print("REGISTO")
            #print(message)
            create_user_db(message.removeprefix("register"),client_socket)
            return False
        elif message.find("login") != -1:

            client_user:client = login_client(message,client_socket)
            lock = threading.Lock()
            lock.acquire()
            for cl in clients:
            #    print(cl.name)
                if cl.name == client_user.name:
                    lock.release()
                    return False
            #print(f"Nome do individuo: {client_user.name}")
            clients.append(client_user)
            #print(list(map(lambda x: f"Nome do individuo: {x.name}",clients)))
            #print("OLA")
            lock.release()
            return False
        elif message.find("getsalt") != -1:
            #print(f"conteudo: {message}")
            get_salt(message.split(".__.")[1],client_socket)
            return False
        else:  
            #print(message)
            try:    
                splitted = message.split('.|||.')
                usrname = splitted[0]
                message = splitted[1]
                #print(usrname)
                #print(message)
                client_user = get_client(usrname,client_socket)

                for cl in clients:
                    if cl.name == client_user.name:
                        cl.socket_info = client_user.socket_info
            except Exception as e:
                print("antes dos ifs")
                print(message)
                print(e.args)
            if message.find("startGROUP") != -1:
                try:
                    message = message.removeprefix("startGROUP")
                    #print(message)
                    messages = message.split(".__.")
                    members_names = messages[0:-2]
                    group_name = messages[-2]
                    signature = messages[-1]
                    #print(group_name)
                    #print(members_names)
                    hand_shake_point_2_point(members_names,client_user,clients,group_name,signature)
                    return False
                except Exception as e:
                    print("STARTGROUP ERROR")
                    print(e.args)
            elif message.find("privateMSG") != -1:
                try:    
                    #print(f"msg: {message}")
                    
                    talk(message.removeprefix("privateMSG"),client_user,clients)
                    
                    #print("FIND")
                    
                    return False
                except Exception as e:
                    print("privateMSG")
                    print(e.args)
            elif message.find("globalMSG") != -1:
                try:
                    #print("global!!!")
                    broadcast(client_user,message.removeprefix("globalMSG"))
                    return False
                except Exception as e:
                    print("GLOBAL-CHAT ERROR")
                    print(e.args)
            elif message.find("exit") != -1:
                return True
    except Exception as e:
        #return True
        print(e.args)       
    return True
    
# Main function to receive the clients connection
def receive(certificate_file,private_key) -> None:
    #print('Server is running and listening ...')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate_file,private_key)
    #context.load_cert_chain('/etc/letsencrypt/live/apolircs.asuscomm.com/fullchain.pem', '/etc/letsencrypt/live/apolircs.asuscomm.com/privkey.pem')
    thread:threading.Thread
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(10)
        with context.wrap_socket(server, server_side=True) as sserver:
            #print(sserver.version())
            while True:
                client, address = sserver.accept()
                online_client_sockets.append(client)
                print(f'connection is established with {str(address)}')
                thread = threading.Thread(target=handle_client, args=([client]))
                thread.start()

        

def start() -> None:
    # Tries to find if there is already an input for the server
    # As it allows the user to startit in 2 different ways
    # So it can be automatized via another script or
    # started manually
    if len(argv) < 3:
        certificate = input("certificate file path\n")
        key = input("key path\n")
        try:
            receive(certificate,key)
            
        except Exception as e:
            print("Error while loading a file")
            print("Check if the path is correct")
            print(f"Exception: {e.args}")
    else:
        try:
            receive(argv[1],argv[2])
            
        except Exception as e:
            print("Error while loading a file")
            print("Check if the path is correct")
            print(f"Exception: {e.args}")

if __name__ == "__main__":
    start()
    