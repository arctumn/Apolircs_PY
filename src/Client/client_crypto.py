import os
from typing import Tuple
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import hashlib

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

def gen_passwd(passwrd:str,salt:bytes, new_user=True) -> Tuple:
    salt = salt.fromhex(salt.decode())
    if new_user:
        salt = os.urandom(32)
    digest = hashlib.sha256(salt + passwrd.encode()).hexdigest()
    #print(f"salt: {salt.hex()}, digest: {digest}")
    return salt.hex(), digest

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
