import socket
import argparse
from random import randrange
# from DH import DiffieHellman, primes, BUFFER_SIZE, asn_encoder, dec
from HandlerAscon import recive_message, send_message
from _thread import start_new_thread

SECRET_KEY = 0
variant = ["Ascon-128", "Ascon-128a", "Ascon-80pq"]
keysize = 20 if variant == "Ascon-80pq" else 16
# ASCON_KEY = ascon.get_random_bytes(keysize) # zero_bytes(keysize)
# nonce = ascon.get_random_bytes(16)      # zero_bytes(16)
key = b'0123456789123456'
nonce = b'1234567890123456'
associateddata = b"MINHHIEU"


def start_client():
    
    ConnectionInfo = argparse.ArgumentParser()
    ConnectionInfo.add_argument("-ip", default = socket.gethostname())
    ConnectionInfo.add_argument("-p", type = int, default = '8080')
    ConnectionInfoParsed = ConnectionInfo.parse_args()
    IP = ConnectionInfoParsed.ip
    PORT = ConnectionInfoParsed.p
    
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print ("[ Socket created ]")
    
    
    print(f"[ Connecting to {IP}:{PORT} ]")
    client_socket.connect((IP, PORT))
    print("[ Connected ]")
    
    return client_socket


if __name__ == "__main__":
    
    sock = start_client()
    
    # Trao đổi khóa
    # keys_exchange(sock)
    
    print("[ Handling incoming messages ]")
    start_new_thread(recive_message, (sock, socket.gethostname(),key, nonce, associateddata, "Ascon-128"))
    send_message(sock, key, nonce, associateddata, "Ascon-128")
    
    sock.close()