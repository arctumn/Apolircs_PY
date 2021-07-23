from ssl import SSLSocket
import OpenSSL as openssl
from OpenSSL.crypto import FILETYPE_PEM, TYPE_RSA

def create_key_pair() -> tuple:
    pkey = openssl.crypto.PKey()
    pkey.generate_key(TYPE_RSA,2048)
    return openssl.crypto.dump_privatekey(FILETYPE_PEM,pkey),openssl.crypto.dump_publickey(FILETYPE_PEM,pkey)

class client:
    name:str
    passwd_hash:str
    passwd_salt:str
    encrypt_mesages:tuple
    sign_mesages:tuple
    socket_info:SSLSocket

    def __init__(self,username,userpasswd_hash,userpasswd_salt,socket:SSLSocket,create_new=True) -> None:
        self.name        = username
        self.passwd_hash = userpasswd_hash
        self.passwd_salt = userpasswd_salt
        self.socket_info = socket
        # gera dois pares de chaves RSA
        #print("here")
        if(create_new):
            self.encrypt_mesages = create_key_pair()
        #print("after-first-pair")
            self.sign_mesages     = create_key_pair()
        #print("after-second-pair")

    def send_to_owner(self) -> None:
        #print("Enviar segredos")
        self.socket_info.send(f"USERINFO".encode('utf-8'))
        #print("Enviar segredos")
        self.socket_info.send(f"SKEY_ENCRYPT:.|||.{self.encrypt_mesages[0]}".encode('utf-8'))
        #print("Enviar segredos")
        self.socket_info.send(f".|||.PKEY_ENCRYPT:.|||.{self.encrypt_mesages[1]}".encode('utf-8'))
        #print("Enviar segredos")
        self.socket_info.send(f".|||.SKEY_SIGN:.|||.{self.sign_mesages[0]}".encode('utf-8'))
        #print("Enviar segredos")
        self.socket_info.send(f".|||.PKEY_SIGN:.|||.{self.sign_mesages[1]}".encode('utf-8'))
        #print("Enviar segredos")

    def send_message(self,message) -> None:
        self.socket_info.send(message)

    def set_online(self,socket):
            self.socket_info = socket

    def __str__(self) -> str:
        return "Nome -> " +self.name
    def sign_key(self):
        return self.sign_mesages[1]
    def enc_key(self):
        return self.encrypt_mesages[1]