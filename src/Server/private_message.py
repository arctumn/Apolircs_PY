from client import client
import threading
grupos = []

def hand_shake_point_2_point(username_of_the_users:list[str],client_send:client,clients:list,group_name:str,signature:str):
    lock = threading.Lock()
    lock.acquire()

    grupos.append((group_name,username_of_the_users))
    #print(grupos)
    lock.release()
    other_clients = list(filter(lambda x: x.name in username_of_the_users,clients))
    #print(list(map(lambda x:"ONLINE: "+ x.name,other_clients)))
    for o_client in other_clients:
        #print("ola")
        try:
            #print(o_client.encrypt_mesages[1])
            #print(client_send.encrypt_mesages[1])
            #print(client_send.socket_info)
            
            client_send.socket_info.send(f"startHAND{group_name}.|||.{o_client.encrypt_mesages[1]}.|||.{signature}".encode())
            #client_send.socket_info.send("ola".encode())
            #print("b")
            msg = client_send.socket_info.recv(3072).decode() + f".|||.{client_send.sign_mesages[1]}" 
            #print(f"{msg} <- ENVIADO")
            #print(o_client.name)
            o_client.send_message(msg.encode())
            #print("enviado")
        except Exception as e:
            print(e.args)
    

def extract_grpup(grupos,nome):
    for grupo in grupos:
        a,b = grupo
        if a == nome:
            return b

def privateMessaging(group_name:str,message:str,clients:list[client],client_sender:client,sig:str) -> None:
    try:
        username_of_the_users = extract_grpup(grupos,group_name)
        #print(username_of_the_users)
        other_clients = list(filter(lambda x: x.name in username_of_the_users,clients))
        print("BIGBIG")
        message = message + ".|||." + sig + ".|||." + client_sender.sign_mesages[1]
        #print(message)
        message = f"privateMSG{group_name}.|||.{message}.|||.{client_sender.name}"
        for cliente in other_clients:
            if cliente.name != client_sender.name:
            #print(f"VALOR DA MSG: {message}")
                cliente.send_message(message.encode('utf-8'))

    except Exception as e:
        print(e.args)

def talk(message:str,client_sender:client,clients:list[client]) -> None:
    group_name, message,sig = message.split(".__.")

    privateMessaging(group_name,message,clients,client_sender,sig)