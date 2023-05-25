import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import string
import secrets
import socket
import sys
from struct import pack, unpack
from base64 import b16encode

DELTA_T = 1


'''
Utility function to send byte stream data with length to the socket. 
Sends the length first by packing it into a 4 byte integer.
'''
def send_data_with_length(data: bytes, socket: socket.socket):
    length = len(data)
    socket.sendall(pack('>I', length))
    socket.sendall(data)

'''
Utility function to receive bytes data from the TCP stream. 
Data is accompanied by its length first.
'''
def recv_data_with_length(s: socket.socket) -> bytes:
    data_len = s.recv(4)
    data_len = unpack('>I', data_len)[0]
    data = s.recv(data_len)
    return data


def bytes_XOR(byte1: bytes, byte2: bytes) -> bytes:
    """
    Calculate the XOR of two byte strings.
    """
    length = max(len(byte1), len(byte2))

    int_var = int.from_bytes(byte1, byteorder = 'big')
    int_key = int.from_bytes(byte2, byteorder = 'big')
    int_enc = int_var ^ int_key
    return int_enc.to_bytes(length, byteorder = 'big')


def main():
    if(len(sys.argv) != 2):
        print("Usage: python3 VU_RegPhase.py <INDEX OF Vi>")
        exit()

    index = int(sys.argv[1])

    # Recv data from TA
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("localhost", 7080))
    s.listen(1)
    conn, addr = s.accept()
    print("Connected to TA")
    
    B = recv_data_with_length(conn)
    E = recv_data_with_length(conn)
    F = recv_data_with_length(conn)
    public_key_bytes_Vi = recv_data_with_length(conn)

    with open(f"Credentials/OBU{index}.txt", 'w') as f:
        f.write(f"B,{b16encode(B).decode()}\n")
        f.write(f"E,{b16encode(E).decode()}\n")
        f.write(f"F,{b16encode(F).decode()}\n")
        f.write(f"PUBLIC_KEY_BYTES,{b16encode(public_key_bytes_Vi).decode()}\n")

    print("Registration successful")




if __name__ == '__main__':
    main()