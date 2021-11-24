
import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from hashlib import sha256
import pyDH
import hashlib
import base64
from Crypto import Random
from Crypto.Cipher import AES
import pyaes

pass_dict={
    "ridham":"12345"
    ,"kanishka":"passw0rd",
    "aadhvan":"rocket",
    "none":"no entry"
}
dict_keys=pass_dict.keys()
def encrypt(plaintext,key):
    key=key.encode('utf-8')
    aes = pyaes.AESModeOfOperationCTR(key)    
    ciphertext = aes.encrypt(plaintext)
    return ciphertext


def decrypt(ciphertext,key):
    key = key.encode('utf-8')
    aes = pyaes.AESModeOfOperationCTR(key)
    decrypted = aes.decrypt(ciphertext).decode('cp855')
    return decrypted
 


server_dh=pyDH.DiffieHellman()
serverdh_pubkey=server_dh.gen_public_key()

keyPair = RSA.generate(bits=1024)
msg = b'A message for signing'
hash = int.from_bytes(sha256(msg).digest(), byteorder='big')
signature = pow(hash, keyPair.d, keyPair.n)
y = [signature,hash,keyPair.e,keyPair.n,serverdh_pubkey]
y=str(y)
y=y.encode()
server_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
LOCALHOST = '127.0.0.1'
port = 9988

server_socket.bind((LOCALHOST,port))
server_socket.listen(5)

print("Server started...")
server_sharedk=int(0)
aes_server=str('')
client_sockets,addr=server_socket.accept()
check=int(0)
first=int(1)
while True:
    msg_received = client_sockets.recv(4096)
    msg_received = msg_received.decode()
    if(msg_received=='hello'):
        client_sockets.send(y)
    else:
        cdh_key=int(msg_received)
        server_sharedk=server_dh.gen_shared_key(cdh_key)
        check=1
    if(check==1):
        while True:
            chat_server = client_sockets.recv(1024)
            # decrypted = decrypt(chat_server, str(server_sharedk))
            tk=str(server_sharedk)
            key = tk[0:16]
            if(first==1):
                first=0;
                fin="server finish"
                bc=encrypt(fin,key).decode('cp855')
                client_sockets.send(bc.encode())
            a=chat_server.decode().encode('cp855')
            # print(type(a))
            name=decrypt(a,key)
            if(name=='client finish'):
                print(name)
                continue
            # print("Client:", decrypt(chat_server.decode(),key))
            n=str(name)
            # msg_send = input("Me:")
            if(n in dict_keys):
                pas=encrypt(pass_dict[n],key).decode('cp855')

                client_sockets.send(pas.encode())
            else:
                pas=encrypt(pass_dict["none"],key).decode('cp855')

                client_sockets.send(pas.encode())



client_sockets.close()
