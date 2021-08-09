import random
import queue
import os
import time

from client_coloring import * #coloring variables

pm_flag = False






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

def print_size():
        rows, columns = os.popen('stty size', 'r').read().split()
        #print(f"comprimento:{columns},altura:{rows}")
        return rows,columns






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


