import ssl
import socket
import random
import queue
import threading
import os
from typing import List, Tuple

import time
from cryptography.fernet import Fernet
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import hashlib




cor_TG = "\033[31m" #Titulos grandes, Global chat e startup
cor_TP = "\033[32m" #lista de amigos e nomes de pessoas
cor_NOT = "\033[33m" #notificações e anúncios
cor_MENU = "\033[36m" #menus e manual
cor_MSG_other = "\033[34m" #mensagens de outras pessoas
cor_MSG = "\033[37m" #mensagens do user
cor_Nome = "\033[35m" #nome do user
cor_BRANCO = "\033[37m"

pm_flag = False


class Receiving(threading.Thread):
    def __init__(self, *args):
        threading.Thread.__init__(self)
        self._event = threading.Event()
        #flag to pause thread
        self.paused = False
        self.pause_cond = threading.Condition(threading.Lock())
        self.args = args
    def run(self):
        while True:
            with self.pause_cond:
                while self.paused:
                    self.pause_cond.wait()
                #thread should do the thing if
                #not paused
                #print(self.args)
                receive_message(self.args[0],self.args[1])
            time.sleep(0.5)

    def pause(self):
        self.paused = True
        # If in sleep, we acquire immediately, otherwise we wait for thread
        # to release condition. In race, worker will still see self.paused
        # and begin waiting until it's set back to False
        self.pause_cond.acquire()

    #should just resume the thread
    def resume(self):
        self.paused = False
        # Notify so thread will wake after lock released
        self.pause_cond.notify()
        # Now release the lock
        self.pause_cond.release()



def menuPM(nome):
    global titpre
    AtualizaHistorico(cor_MENU + "Insira o nome dos destinatários separados por espaço: "  + cor_BRANCO)
    ambienteGrafico()
    destino = input(cor_Nome + f"<{nome}> " + cor_MSG)
    lista = destino.split(' ')
    AtualizaHistorico(cor_Nome + f"<{nome}>" + cor_MSG + destino + cor_BRANCO)
    destino = ""
    for a in lista:
        destino += a + ".__."
    ambienteGrafico()
    if len(lista) != 1:
        AtualizaHistorico(cor_MENU + "Insira o nome da conversa: " + cor_BRANCO)
        ambienteGrafico()
        titpre = input(cor_Nome + f"<{nome}> " + cor_MSG)
        AtualizaHistorico(cor_Nome + f"<{nome}>" + cor_MSG  + titpre + cor_BRANCO)
    else:
        titpre = lista[0] + str(random.randint(0,9999))
    return destino, lista

def ListaCores():
    AtualizaHistorico(cor_MENU + "Cores disponíveis:" + cor_BRANCO)
    AtualizaHistorico("")
    AtualizaHistorico('\033[30m' + "1) BLACK" + '\033[37m')
    AtualizaHistorico('\033[31m' + "2) RED" + cor_BRANCO)
    AtualizaHistorico('\033[32m' + "3) GREEN" + cor_BRANCO)
    AtualizaHistorico('\033[33m' + "4) YELLOW" + cor_BRANCO)
    AtualizaHistorico('\033[34m' + "5) BLUE" + cor_BRANCO)
    AtualizaHistorico('\033[35m' + "6) MAGENTA" + cor_BRANCO)
    AtualizaHistorico('\033[36m' + "7) CYAN" + cor_BRANCO)
    AtualizaHistorico('\033[37m' + "8) WHITE" + cor_BRANCO)
    AtualizaHistorico("")
    ambienteGrafico()
    opcao = input(cor_MENU + "Por favor escreva o número da cor pretendida: " + cor_BRANCO)
    if opcao == "1":
        return "\033[30m" #BLACK
    elif opcao == "2":
        return "\033[31m" #RED
    elif opcao == "3":
        return "\033[32m" #GREEN
    elif opcao == "4":
        return "\033[33m" #YELLOW
    elif opcao == "5":
        return "\033[34m" #BLUE
    elif opcao == "6":
        return "\033[35m" #MAGENTA
    elif opcao == "7":
        return "\033[36m" #CYAN
    elif opcao == "8":
        return "\033[37m" #WHITE

def mudarCor(opcao:str):
    global cor_TG
    global cor_TP
    global cor_NOT
    global cor_MENU
    global cor_MSG_other
    global cor_MSG
    global cor_Nome

    if opcao == "1":
        cor_TG = ListaCores()
    elif opcao == "2":
        cor_TP = ListaCores()
    elif opcao == "3":
        cor_NOT = ListaCores()
    elif opcao == "4":
        cor_MENU = ListaCores()
    elif opcao == "5":
        cor_MSG_other = ListaCores()
    elif opcao == "6":
        cor_MSG = ListaCores()
    elif opcao == "7":
        cor_Nome = ListaCores()

def messageParse(msg:str):
    if msg == "!help":
        AtualizaHistorico(cor_MENU + "ICHATO MANUAL:" + cor_BRANCO)
        AtualizaHistorico("")
        AtualizaHistorico(cor_MENU + "!help -> Abre este manual." + cor_BRANCO)
        AtualizaHistorico(cor_MENU + "!exit -> Fecha o chat actual." + cor_BRANCO)
        AtualizaHistorico(cor_MENU + "!pm -> Inicia o menu de escolha de grupos." + cor_BRANCO)
        AtualizaHistorico(cor_MENU + "!pm (x) -> Inicia uma mensagem privada com o utilizador/grupo x." + cor_BRANCO)
        AtualizaHistorico(cor_MENU + "!cor -> Abre o menu de opções de cor." + cor_BRANCO)
        AtualizaHistorico("")
        return 1
    elif msg == "!cor":
        while(msg != "8"):
            AtualizaHistorico(cor_MENU + "MENU DE DEFINIÇÕES DE COR:" + cor_BRANCO)
            AtualizaHistorico("")
            AtualizaHistorico(cor_MENU + "1 -> Mudar a cor dos títulos" + cor_BRANCO)
            AtualizaHistorico(cor_MENU + "2 -> Mudar a cor da lista de chats e nomes de pessoas" + cor_BRANCO)
            AtualizaHistorico(cor_MENU + "3 -> Mudar a cor das notificações e anúncios" + cor_BRANCO)
            AtualizaHistorico(cor_MENU + "4 -> Mudar a cor dos menus e manual" + cor_BRANCO)
            AtualizaHistorico(cor_MENU + "5 -> Mudar a cor das mensagens de outras pessoas" + cor_BRANCO)
            AtualizaHistorico(cor_MENU + "6 -> Mudar a cor das minhas mensagens" + cor_BRANCO)
            AtualizaHistorico(cor_MENU + "7 -> Mudar a cor do meu nome" + cor_BRANCO)
            AtualizaHistorico(cor_MENU + "8 -> Sair do menu" + cor_BRANCO)
            ambienteGrafico()
            msg = input(cor_MENU + "> " + cor_BRANCO)
            mudarCor(msg)
        return 1
    elif msg == "!teste":
        AddListaAmigos(calculaEspacos(20,titpre),3, True)
        return 1
    elif msg == "!exit":
        return 1
    elif (str(msg).casefold().find("!pm") != -1):
        return 1
    else:
        return 0

def inicializaAmigos(): # Inicializa a lista amigos com strings de 20 espaços
    amigos = [(str,int)]
    y = 0
    while(y < 60):
    #    amigos.append(f"{y} - ")
        amigos.append(("",0))
        y += 1
    c = -1
    for i in amigos:
        frase = ""
        c += 1
        y = 0
        limite = 20
        while(y < limite):
            y += 1
            #if c > 9:
            #    limite = 19
            frase += " "
        amigos[c] = (frase,0)
    return amigos

def inicializaHistorico():
    historico = []
    y = 0
    while(y < 61):
    #    historico.append(f"{y} - ")
        historico.append("")
        y += 1
    return historico

def inicializaListaMSG():
    lista = [(str, queue.Queue(50))] # nome chat, queue
    #a = queue.Queue(1)
    #a.put("teste->adeus")
    #lista.append(("Global Chat",a))
    return lista

def getMessagesUSer(lista:list, nome:str) -> queue.Queue:
    for a in lista:
        c,b = a
        if c == nome:
            return b

def guardaMSG(nome:str, msg:str):
    existe = False
    for a in ListaMsgs:
        c,b = a
        if c == nome:
            b.put(msg)
            existe = True
            return
    if not existe:
        a = queue.Queue(50)
        a.put(msg)
        ListaMsgs.append((nome,a))
    

historico = inicializaHistorico()
amigos = inicializaAmigos()
ListaMsgs = inicializaListaMSG()
titpre = "" #Titulo pre-formatação
tamH = 120
tamV = 20

def calculaEspacos(tam, msg:str):
    i = 0
    nesp = tam - len(msg)
    lado = nesp//2
    retorno = ""
    if nesp % 2 == 1:
        retorno = " "
    while(i < lado):
        retorno += " "
        i += 1
    retorno += msg
    i = 0
    while(i < lado):
        retorno += " "
        i += 1
    return retorno

def AddListaAmigos(e:str, n:int, add:bool):
    i = 0
    counter = 0
    for a in amigos:
        c,b = a
        #print(c)
        if c == e:
            if add:
                amigos[counter] = (c, b+n)
            else:
                amigos[counter] = (c, n)
            return
        counter += 1
    while(i < 20):
        if amigos[i][0] != "                    ":
            #print("String preenchida")
            i += 1
            continue
        else:
            #print("Entrei")
            #print(amigos[i][0])
            #print(e)
            a,b = amigos[i]
            if add:
                amigos[i] = (e, b+n)
            else:
                amigos[i] = (e, n)
            #print(amigos[i][0])
            return
    return

def getNAmigos(e:str):
    for a in amigos:
        c,b = a
        if c == e:
            return b
    return 0

def RemListaAmigos(e):
    i = 0
    flag = 0
    while(i < 20):
        c,_ = amigos[i]
        if flag == 1:
            if i == 20:
                amigos[20] = ("                    ",0)
                #print("Estou na flag")
                return
            amigos[i] = amigos[i+1]
        elif c == e:
            #print("Encontrei")
            if i == 20:
                #print("Encontrei último")
                amigos[20] = ("                    ",0)
                return
            #print("Encontrei 2")
            amigos[i] = amigos[i+1]
            flag = 1
        i += 1

def AtualizaHistorico(mensagem):
    i = 60
    #print("VOU ENTRAR NO WHILE")
    while(i > -1):
        #print("ENTREI NO WHILE")
        if i == 0:
            #print("Última mensagem")
            historico[0] = mensagem
            return
        #print(f"A actualizar mensagem: {i}, {historico[i]} = {historico[i-1]}")
        historico[i] = historico[i-1]
        i -= 1
    return
        
def ambienteGrafico():
    os.system('cls' if os.name == 'nt' else 'clear')

    #alt, larg = print_size()
    #if alt > 150:
    #    tamV = 10

    #if larg > 150:
    #    tamH = 150
    
    #if larg < 100:
    #    tamH = 80
    global tamH
    global tamV

    titulo = calculaEspacos(tamH-2, titpre)

    extVert = [f'''\n    |{cor_TP}{amigos[i][0]}{f" {cor_NOT}({amigos[i][1]})" if amigos[i][1] != 0 else "    "}{cor_BRANCO}|{historico[tamV-i]}''' for i in range(tamV+1)]
    out = ""
    [ out := out + x for x in extVert]

    tr = ""
    for _ in range(tamH):
        tr += "_"
    esp = ""
    for _ in range(tamH):
        esp += " "

    print(f'''
     {cor_BRANCO + tr}
    |{esp}|
    |{cor_TG} {titulo} {cor_BRANCO}|
    |{tr}|
    |                        |{out}
    |________________________|''', end='')

#{["\n    |                        |" for i in range(tamV)]}

def debug_admin(msg:str) -> None:
    AtualizaHistorico(cor_TP + "<ADMIN>" + cor_MSG_other + msg + cor_BRANCO)
    ambienteGrafico()


def sign(msg:bytes,user:str) -> str:
    #debug_admin(msg.decode())
    #debug_admin(user)
    #debug_admin(str("a","b"))
    with open(f"{user}_skey_sign.pem","rb") as key_file:
        #debug_admin(user)
        key_f = key_file.read()
        #debug_admin(key_f.decode())
        sign_key = serialization.load_pem_private_key(
            key_f,
            password=None,
            )
        key_file.close()

        sig = sign_key.sign(
            msg,
            padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
        )
        #debug_admin(sig.hex())
        return sig.hex()

def encrypt_with_shared_key(group_name:str,  msg:str) -> str:
    msg = msg.encode()
    with open(f"{group_name}_shared_key.pem","rb") as gkey:
        fernet = Fernet(gkey.read())
        gkey.close()
        return fernet.encrypt(msg).hex()

def decrypt_with_shared_key(group_name:str, msg:str) -> str:
    cifred_text = bytes.fromhex(msg)
    with open(f"{group_name}_shared_key.pem","rb") as gkey:
        fernet = Fernet(gkey.read())
        gkey.close()
        return fernet.decrypt(cifred_text).decode()

def receive_hand_shake(socket:ssl.SSLSocket,group_name:str,cifred_key:bytes,signature:bytes,p_key_sign:bytes,user_name:str):
   
    msg = decrypt(cifred_key,user_name)
    if verify(msg.encode(),bytes.fromhex(bytes.hex(signature)),p_key_sign) == "SUCCESS":
        with open(f"{group_name}_shared_key.pem","w") as f:
            f.write(msg)
            f.close()

def verify(msg,signature,key) -> str:

    key_splitted = key.decode().replace("\\n",".|||.").split(".|||.")
    with open("temp_sign.pem","w") as f:
        for line in key_splitted:
            if line:
                f.write(line+"\n")
        f.close()
    try:
        with open("temp_sign.pem","rb") as key_bin:
            public_key = serialization.load_pem_public_key(key_bin.read())
            key_bin.close()
        public_key.verify(
            signature,
            msg,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return "SUCCESS"
    except Exception as e:
        return "ERROR"

def print_size():
        rows, columns = os.popen('stty size', 'r').read().split()
        #print(f"comprimento:{columns},altura:{rows}")
        return rows,columns

def gen_passwd(passwrd:str,salt:bytes, new_user=True) -> Tuple:
    salt = salt.fromhex(salt.decode())
    if new_user:
        salt = os.urandom(32)
    digest = hashlib.sha256(salt + passwrd.encode()).hexdigest()
    #print(f"salt: {salt.hex()}, digest: {digest}")
    return salt.hex(), digest

def register(ssock:ssl.SSLSocket) -> Tuple:
    #rand = random.randint(0,1000)
    nome = input("Qual o seu nome? ")
    passwrd = input("Qual a sua password? ")
    salt, digested_password = gen_passwd(passwrd,"".encode(),True)
    ssock.send(f"register.__.{nome}.__.{digested_password}.__.{salt}".encode())
    ssock.recv(1024)
    allkeys= f'''{ssock.recv(3100).decode().removesuffix("'")}{ssock.recv(3100).decode().removesuffix("'")}{ssock.recv(3100).decode().removesuffix("'")}{ssock.recv(3100).decode().removesuffix("'")}'''
    #print(allkeys)
    try:
        save_keys(allkeys,f"{nome}")
    except Exception as e:
        print(e.args)
    return nome

def login(ssock:ssl.SSLSocket) -> str:
    counter = 0
    while True:
        if counter == 3:
            return ""
        nome = input("Qual o nome? ")
        password = input ("Qual a password? ")
        #print("teste")
        ssock.send(f"getsalt.__.{nome}".encode())
        #print("teste")
        salt = ssock.recv(1024)
        #print(f"salt-> {salt}")
        if salt:
            ssock.send(f"login.__.{nome}.__.{gen_passwd(password,salt, False)[1]}".encode('utf-8'))
            resp = ssock.recv(1024).decode()
            #print(resp)
            if resp == "Online":
                return nome
        print("Erro no login tente novamente!")
        counter += 1

def save_keys(message:str,user:str):
    with open("debug.txt","w") as f:
        n_messages = message.split("\n")
        f.writelines(n_messages)
        f.close()
    strings    = message.split(".|||.")
    name_files = [f"{user}_skey_encrypt.pem",f"{user}_pkey_encrypt.pem",f"{user}_skey_sign.pem",f"{user}_pkey_sign.pem"]
    keys       = []
    for i in range(1,len(strings),2):
        keys.append(strings[i].removeprefix("b'"))
    for i in range(len(keys)):
        #print(str(keys[i]).strip())
        key:str = keys[i]
        key_splitted = key.replace("\\n",".|||.").split(".|||.")
        with open(name_files[i],"w") as f:
            for line in key_splitted:
                if line:
                    f.write(line+"\n")
            f.close()

def encrypt(message,key) -> bytes:
    key_splitted = key.decode().replace("\\n",".|||.").split(".|||.")
    with open("temp_enc.pem","w") as f:
        for line in key_splitted:
            if line:
                f.write(line+"\n")
        f.close()
    with open(f"temp_enc.pem","rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    key_file.close()
    res = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    #print(f"VALOR ENCRIPTADO:-> {res}")
    return res

def decrypt(message:bytes,user:str) -> str:
    with open(f"{user}_skey_encrypt.pem","rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )
        key_file.close()
    return private_key.decrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()

thread_receber:Receiving

def make_key(from_user,group_name):
    global common_shared
    shared_key = Fernet.generate_key()
    signatures = sign(shared_key,from_user)
    #debug_admin(str(len(to_users)))
    with open(f"{group_name}_shared_key.pem","w") as f:
            f.write(shared_key.decode())
            f.close()
    common_shared = shared_key
    return signatures
            
def send_hand_shake_to_group(socket:ssl.SSLSocket,group_name:str,usr_pkey:bytes,signatures:str) -> None:
    #thread_receber.pause()
    global common_shared
    shared_key = common_shared
    #debug_admin("FOOOOOOOOOOOOOOOOOOOOR")
    try:     
        cifrado = encrypt(shared_key,usr_pkey)
        msg = f"send_handshake.|||.{group_name}.|||.{bytes.hex(cifrado)}.|||.{signatures}"
    except Exception as e:
        print(e.args)
        print("ERRORR")
        #thread_receber.resume()
        exit(-1)
    socket.send(msg.encode())
    #thread_receber.resume()
    
    

def startup():

    tempo = 0.000
    global titpre
    titpre = "Global Chat"

    ambienteGrafico()
    time.sleep(tempo)
    AtualizaHistorico(cor_TG + " ___ ____ _   _    _  _____ ___  " + cor_BRANCO)
    ambienteGrafico()
    time.sleep(tempo)
    AtualizaHistorico(cor_TG + "|_ _/ ___| | | |  / \|_   _/ _ \ " + cor_BRANCO)
    ambienteGrafico()
    time.sleep(tempo)
    AtualizaHistorico(cor_TG + " | | |   | |_| | / _ \ | || | | |" + cor_BRANCO)
    ambienteGrafico()
    time.sleep(tempo)
    AtualizaHistorico(cor_TG + " | | |___|  _  |/ ___ \| || |_| |" + cor_BRANCO)
    ambienteGrafico()
    time.sleep(tempo)
    AtualizaHistorico(cor_TG + "|___\____|_| |_/_/   \_\_| \___/ " + cor_BRANCO)
    ambienteGrafico()
    time.sleep(tempo)
    AtualizaHistorico("")
    ambienteGrafico()
    time.sleep(tempo)
    AtualizaHistorico("")
    ambienteGrafico()
    time.sleep(tempo)
    AtualizaHistorico(cor_TG + " _           " + cor_BRANCO)
    ambienteGrafico()
    time.sleep(tempo)
    AtualizaHistorico(cor_TG + "| |__  _   _ " + cor_BRANCO)
    ambienteGrafico()
    time.sleep(tempo)
    AtualizaHistorico(cor_TG + "| '_ \| | | |" + cor_BRANCO)
    ambienteGrafico()
    time.sleep(tempo)
    AtualizaHistorico(cor_TG + "| |_) | |_| |" + cor_BRANCO)
    ambienteGrafico()
    time.sleep(tempo)
    AtualizaHistorico(cor_TG + "|_.__/ \__, |" + cor_BRANCO)
    ambienteGrafico()
    time.sleep(tempo)
    AtualizaHistorico(cor_TG + "       |___/ " + cor_BRANCO)
    ambienteGrafico()
    time.sleep(tempo)
    AtualizaHistorico("")
    ambienteGrafico()
    time.sleep(tempo)
    AtualizaHistorico("")
    ambienteGrafico()
    time.sleep(tempo)
    AtualizaHistorico(cor_TG + "    _    ____   ___  _     ___ ____   ____ ____  " + cor_BRANCO)
    ambienteGrafico()
    time.sleep(tempo)
    AtualizaHistorico(cor_TG + "   / \  |  _ \ / _ \| |   |_ _|  _ \ / ___/ ___| " + cor_BRANCO)
    ambienteGrafico()
    time.sleep(tempo)
    AtualizaHistorico(cor_TG + "  / _ \ | |_) | | | | |    | || |_) | |   \___ \ " + cor_BRANCO)
    ambienteGrafico()
    time.sleep(tempo)
    AtualizaHistorico(cor_TG + " / ___ \|  __/| |_| | |___ | ||  _ <| |___ ___) |" + cor_BRANCO)
    ambienteGrafico()
    time.sleep(tempo)
    AtualizaHistorico(cor_TG + "/_/   \_\_|    \___/|_____|___|_| \_\\_____|_____/ " + cor_BRANCO)
    ambienteGrafico()
    time.sleep(tempo)
    AtualizaHistorico("")
    ambienteGrafico()
    time.sleep(tempo)
    AtualizaHistorico("")
    ambienteGrafico()
    for _ in range(17):
        time.sleep(tempo)
        AtualizaHistorico("")
        ambienteGrafico()

#waiting_msg = queue.Queue(10)

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
        print("ERRRO")
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
    

def receive_message(socket:ssl.SSLSocket,nome:str) -> None:
        #if(not pm_flag):
        try:
            #debug_admin(str("receber"))
            msg = socket.recv(3072)
            #debug_admin(msg.decode())
            #debug_admin(msg.decode()) if msg.decode() != "" else ""
            parse_received(msg,nome,socket) if msg.decode() != "" else ""
        except Exception as e:
            print(e.args)

def ImprimeMensagensGuardadas(chat):
    global ListaMsgs
    try:
        for a in ListaMsgs:
            ##print("ENTREI")
            c,b = a
            if c == chat:
                ##print("c = " + c)
                while not b.empty():
                    if c == "Global Chat":
                        ##print("Entrei na verificação")
                        teste = b.get()
                        #print(teste)
                        other_nome,mensagem = teste.split("->")
                        #print(other_nome + " " + mensagem )
                        AtualizaHistorico(cor_TP + f"<{other_nome.strip()}> " + cor_MSG_other + mensagem + cor_BRANCO)
                        ambienteGrafico()                        
                    else:    
                        teste = b.get()
                        mensagem,rem = teste.split(".|||.")
                        AtualizaHistorico(cor_TP + f"<{rem.strip()}> " + cor_MSG_other + mensagem + cor_BRANCO)
                        pass
    except Exception as e:
        print(e.args)
    return

def send_message(soc:ssl.SSLSocket, nome:str):
    global titpre
    modo = -1
    startup()
    AddListaAmigos(calculaEspacos(20,"Global Chat"), 0, False)

    AtualizaHistorico(cor_MENU + "Escolha o tipo de mensagem:" + cor_BRANCO)
    AtualizaHistorico(cor_MENU + "1 - Mensagem Global" + cor_BRANCO)
    AtualizaHistorico(cor_MENU + "2 - Mensagem Privada " + cor_BRANCO)
    AtualizaHistorico(cor_MENU + "3 - Sair" + cor_BRANCO)
    ambienteGrafico()
    resposta = input(cor_MENU + "> " + cor_MSG)
    msg = ""
    if resposta == "1": # MENSAGENS GLOBAIS
        modo = 1
        titpre = "Global Chat"
        AtualizaHistorico(calculaEspacos(122,cor_NOT + f" ### ESTÁ AGORA NO CHAT: { cor_TP + titpre + cor_NOT} ###" + cor_BRANCO))
        ImprimeMensagensGuardadas("Global Chat")
        #mensagens_globais = getMessagesUSer(ListaMsgs,"Global Chat")
#        while(msg != "!exit"):
#            #debug_admin(msg)
#            ambienteGrafico()
#            msg = input(cor_Nome + f"<{nome}> " + cor_MSG)
#            AtualizaHistorico(cor_Nome + f"<{nome}> " + cor_MSG + msg + cor_BRANCO)
#            
#            ImprimeMensagensGuardadas("Global Chat")
                #msg = input(f"|________________________| {nome}:",end="\r")
                ##print("a não")
                ##print("a")
#            if messageParse(msg) != 1:
#                ambienteGrafico()
                ##print("Mensagem: "+ msg)
#                try:
#                    if msg != "":
#                        signature = sign(msg.encode(),nome)
#                        new_msg = f"{nome}.|||.globalMSG{msg}.__.{signature}"
                        #debug_admin(new_msg)
#                        soc.sendall(new_msg.encode('utf-8'))
#                except:
#                    debug_admin(msg)
                
    elif resposta == "2": # MENSAGENS PRIVADAS
        modo = 2
        nome_utilizadores, listausers = menuPM(nome)
        signature = make_key(nome,titpre)
        snd_msg = f"{nome}.|||.startGROUP{nome_utilizadores}{titpre}.__.{signature}"
        soc.send(snd_msg.encode())
        #debug_admin("HERE")
            #send_hand_shake_to_group(soc,nome, listausers, titpre)
            #thread_receber.resume()
        AtualizaHistorico(calculaEspacos(122,cor_NOT + f" ### ESTÁ AGORA NO CHAT: { cor_TP + titpre + cor_NOT} ###" + cor_BRANCO))
        AddListaAmigos(calculaEspacos(20,titpre),0, False)
        ambienteGrafico()

    elif resposta == "3":
        exit(0)
    else:
        #print(cor_MENU + "Opção não reconhecida" + cor_BRANCO)
        send_message(soc,nome)

    while(msg != "!exit"):
        
        ImprimeMensagensGuardadas(titpre)
        ambienteGrafico()
        msg = input(cor_Nome + f"<{nome}> " + cor_MSG)
        AtualizaHistorico(cor_Nome + f"<{nome}> " + cor_MSG + msg + cor_BRANCO)
        ambienteGrafico()

        if msg == "!pm":
            modo = 2
            destino, listausers = menuPM(nome)
            signature = make_key(nome,titpre)
            soc.send(f"{nome}.|||.startGROUP{destino}{titpre}.__.{signature}".encode('utf-8')) #ATENÇÃO, o for já add o .__. a seguir ao destino
            #send_hand_shake_to_group(soc,nome, listausers, titpre)
            AtualizaHistorico(calculaEspacos(122,cor_NOT + f" ### ESTÁ AGORA NO CHAT: { cor_TP + titpre + cor_NOT} ###" + cor_BRANCO))
            AddListaAmigos(calculaEspacos(20,titpre),0, False)
            ambienteGrafico()


        elif (str(msg).casefold().find("!pm ") != -1):
            modo = 2
            #debug_admin(msg)
            grupo = msg.removeprefix("!pm ")
            #grupo = msg[4:]
            #debug_admin(grupo)
            if grupo == "Global Chat":
                modo = 1
                titpre = "Global Chat"
            else:
                titpre = grupo
                #titpre = grupo + str(random.randint(0,9999))
            #debug_admin(grupo)
            AddListaAmigos(calculaEspacos(20,titpre),0, False)
            AtualizaHistorico(calculaEspacos(122,cor_NOT + f" ### ESTÁ AGORA NO CHAT: { cor_TP + titpre + cor_NOT} ###" + cor_BRANCO))
            ImprimeMensagensGuardadas(titpre)
            ambienteGrafico()
            # if grupo não existe então:
            #   destino = menuPM(nome)
            #   soc.send(f"{nome}.|||.startGROUP{destino}{titpre}".encode('utf-8')) #ATENÇÃO, o for já add o .__. a seguir ao destino
            #   AtualizaHistorico(calculaEspacos(122,f" ### ESTÁ AGORA NO CHAT: {titpre} ###"))
            #   ambienteGrafico()

        elif modo == 1:
            ImprimeMensagensGuardadas("Global Chat")
            if messageParse(msg) != 1:
                ambienteGrafico()
                ##print("Mensagem: "+ msg)
                try:
                    if msg != "":
                        signature = sign(msg.encode(),nome)
                        new_msg = f"{nome}.|||.globalMSG{msg}.__.{signature}"
                        #debug_admin(new_msg)
                        soc.sendall(new_msg.encode('utf-8'))
                except Exception as e:
                    print(e.args)
                    #debug_admin(msg)

        elif modo == 2:
            ImprimeMensagensGuardadas(titpre)
            if messageParse(msg) != 1:
                try:
                    if msg != "":
                        sig = sign(msg.encode(),nome)
                        #print(sig)
                        msg = encrypt_with_shared_key(titpre,msg)
                        soc.send(f"{nome}.|||.privateMSG{titpre}.__.{msg}.__.{sig}".encode('utf-8'))
                except Exception as e:
                    print(e.args)
                    #debug_admin(msg)


def inicio(soc):
    print('''
 ___ ____ _   _    _  _____ ___  
|_ _/ ___| | | |  / \|_   _/ _ \ 
 | | |   | |_| | / _ \ | || | | |
 | | |___|  _  |/ ___ \| || |_| |
|___\____|_| |_/_/   \_\_| \___/ ''')
    resposta = input("\nBem-vindo ao iChato!\n" + 
        "\n1 - Iniciar sessão" +
        "\n2 - Registar Utilizador" +
        "\n> ")
    if resposta == "2":
        nome = register(ssock)
        print("Iniciar sessão: ")
        login(ssock)
    elif resposta == "1":
        nome = login(ssock)
    else:
        print("Opção não reconhecida")
        return inicio(soc)
    return nome

hostname = 'apolircs.asuscomm.com'
# PROTOCOL_TLS_CLIENT requires valid cert chain and hostname
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context = ssl.create_default_context()

with socket.create_connection((hostname, 4004)) as sock:
    with context.wrap_socket(sock, server_hostname=hostname) as ssock:

        nome = inicio(ssock)
        thread_receber = Receiving(ssock,nome)
        thread_receber.start()
        try:
            while(True):
                
                #thread_receber = threading.Thread(target=receive_message, args=([ssock,nome]))
                #thread_receber_events = threading.Event()
                #thread.daemon = True
                #thread_receber.
                send_message(ssock,nome)

        except Exception as e:
            print(e.args)
            ssock.send(f"exit".encode())
            ssock.close()