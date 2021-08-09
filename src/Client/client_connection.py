import threading
import time
import ssl
import socket
from typing import Tuple
from cliente_grafico import startup, AddListaAmigos, calculaEspacos, AtualizaHistorico, ambienteGrafico, ImprimeMensagensGuardadas, menuPM, titpre, messageParse
from client_parsing import receive_message
from client_crypto import make_key, sign, encrypt_with_shared_key, gen_passwd, save_keys
from client_coloring import *


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

def start() -> None:
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
            destino, _ = menuPM(nome)
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

def inicio(ssock):
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
        return inicio(ssock)
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