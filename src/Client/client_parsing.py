from client_crypto import verify,decrypt_with_shared_key
from client_connection import ssl, receive_hand_shake, send_hand_shake_to_group
from cliente_grafico import *
def parse_received(msg:bytes,nome:str,ssock:ssl.SSLSocket) -> None:
    try:
        
        if msg.decode().find("globalMSG") != -1:
            send_to_buffer(msg.decode())
           
        elif msg.decode().find("send_handshake") != -1:
           
            incoming = msg.decode().removeprefix("send_handshake.|||.")
           
            group_name,cifred_key,signature,pkey = incoming.split(".|||.")
            
            receive_hand_shake(ssock,group_name,bytes.fromhex(cifred_key),bytes.fromhex(signature),pkey.encode(),nome)

        elif msg.decode().find("startHAND") != -1:
           
            group_name,pkey,signature = msg.decode().removeprefix("startHAND").split(".|||.")
            send_hand_shake_to_group(ssock,group_name,pkey.encode(),signature)
        
        elif msg.decode().find("privateMSG") != -1:
            group_name,message,sig,pkey,remetente = msg.decode().removeprefix("privateMSG").split(".|||.")
            msg_to_verify = decrypt_with_shared_key(group_name,message)
            if verify(msg_to_verify.encode(),bytes.fromhex(sig),pkey.encode()) == "SUCCESS":
                send_to_private_buffer(msg_to_verify + ".|||." + remetente,group_name)
    except Exception as e:
        #debug_admin("FIM")
        print(e.args)
        exit(1)
    
def check_global_msg(msg:str):
    try:
        mensagem,signature,psign_key = msg.split(".__.")
        #print(bytes.fromhex(signature))
        mensagem_to_validate = mensagem.split(" -> ")[1]
        if verify(mensagem_to_validate.encode(),bytes.fromhex(signature),psign_key.encode()) == "SUCCESS":
            #print("OLA_SUUCESSO")
            return mensagem
        return ""
    except Exception as e:
        print("Error")
        print(mensagem_to_validate)
        print(e.args)
        return ""

def send_to_private_buffer(msg:str,group_name:str) -> None:
    global ListaMsgs
    if msg == "":
        return
    if titpre != group_name:
        AddListaAmigos(calculaEspacos(20,group_name), 1, True)
    guardaMSG(group_name,msg)

def send_to_buffer(msg:str):
    global ListaMsgs

    try:
        msg = check_global_msg(msg).removeprefix("globalMSG")

    except Exception as e:
        print(e.args)
        exit(1)
        #debug_admin(msg) if msg != "" else ""

    if msg == "":
        return
    if titpre != "Global Chat":
        AddListaAmigos(calculaEspacos(20,"Global Chat"), 1, True)
    guardaMSG("Global Chat", msg)
