import socket
from Crypto.PublicKey import RSA
from hashlib import sha256
import pyDH
client_dh = pyDH.DiffieHellman()
import hashlib
import base64
from Crypto import Random
import pyaes
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
 

server_key=int(0)
aes_client=str('')
sig_mes=[]
clientdh_pubkey=client_dh.gen_public_key()
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
LOCALHOST = '127.0.0.1'
port = 9988

s.connect((LOCALHOST,port))
print("New client created:")
first=int(0)
client_sharedk=int(0)
while True:
    if(first==0):
        client_message = 'hello'
        first=1
        s.send(client_message.encode())

    msg_received = s.recv(4096)
    sig_mes = msg_received.decode()
    sig_res=sig_mes.strip('][').split(', ')
    signature=int(sig_res[0])
    myhash=int(sig_res[1])
    ke=int(sig_res[2])
    kn=int(sig_res[3])
    sdh_key=int(sig_res[4])
    hashFromSignature = pow(signature,ke,kn)
    if(hashFromSignature==myhash):
        print("signature verified")
        client_sharedk=client_dh.gen_shared_key(sdh_key)
        cpk=str(clientdh_pubkey)
        cpk=cpk.encode()
        s.send(cpk)
    else:
        print("signature wrong")
        break

    first=int(0)
    # print("Server:",msg_received)
    while True:
        tk=str(client_sharedk)
        key = tk[0:16]
        if(first==0):
            first=1
            fin="client finish"
            t=encrypt(fin,key).decode('cp855')
            s.send(t.encode())
            msg_received = s.recv(1024)
            msg_received = msg_received.decode('cp855')
            # print("Server:",msg_received)

            continue

        client_message = input("Me: ")
        temp=encrypt(client_message,key).decode('cp855')
        s.send(temp.encode())

        msg_received = s.recv(1024)
        msg_received = msg_received.decode().encode('cp855')
        m1=decrypt(msg_received,key)
        # if(len(m1)<=2):
        #     print("Server:","no entry")
        print("Server:",m1)

        # if msg_received == 'exit':
        #     break;
s.close()
