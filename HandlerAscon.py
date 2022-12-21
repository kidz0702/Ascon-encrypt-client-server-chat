import ascon
# from random import randint as r
# from random import choice as pl  
import time
from datetime import datetime

# current timestamp

# print("Timestamp:", x)

import socket
BUFFER_SIZE = 4096

# variant = ["Ascon-128", "Ascon-128a", "Ascon-80pq"]
# keysize = 20 if variant == "Ascon-80pq" else 16
# ASCON_KEY = ascon.get_random_bytes(keysize) # zero_bytes(keysize)
# nonce = ascon.get_random_bytes(16)      # zero_bytes(16)
# associateddata = b"MINHHIEU"

def recive_message(sock: socket, addr: str, key: bytes, nonce: bytes, assdata: bytes, variant: str) -> None:
    assert variant in ["Ascon-128", "Ascon-128a", "Ascon-80pq"]
    while True:
        try:
            # msg = sock.recv(BUFFER_SIZE).decode('utf-8')
            # ts = time.time()
            dt = datetime.now()
            # str_dt = dt.strftime("%d-%m-%Y, %H:%M:%S")
            
            msg = sock.recv(BUFFER_SIZE)
            # msg = AESCipher(msg, str(secret)).decrypt()
            msg = ascon.ascon_decrypt(key, nonce, assdata, msg, variant)
            if msg == None: print("verification failed!")
            
            if not msg:
                break
            print(f"\r{addr} : {msg} - {dt}")
            print("\r> ", end="")
        except socket.error:
            print("[ ERROR: Could not recive message ]")
            break
        except ValueError:
            break

    print(f"[ Connection with {addr} closed ]\n")
    sock.close()   
    
def send_message(sock: socket, key: bytes, nonce: bytes, assdata: bytes, variant: str) -> None:
    assert variant in ["Ascon-128", "Ascon-128a", "Ascon-80pq"]
    while True:
        # msg = input("> ").encode('utf-8')
        # ts = time.time()
        dt = datetime.now()
        # str_dt = dt.strftime("%d-%m-%Y, %H:%M:%S")
        
        msg = input("> ").encode('utf-8')
        print(f"\r> sent at: {dt}")
        # msg = dt + msg
        if not msg:
            break
        # encrypt_client = AESCipher(msg, str(secret)).encrypt()
        encrypt_client = ascon.ascon_encrypt(key, nonce, assdata, msg, variant) 
        try:
            sock.sendall(encrypt_client)
        except socket.error:
            print("[ ERROR: Could not send message ]")
            break
        
    print(f"[ Connection closed ]\n")
    sock.close()

def recieve(sock: socket) -> str:
    msg = sock.recv(BUFFER_SIZE).decode("utf-8")
    return msg