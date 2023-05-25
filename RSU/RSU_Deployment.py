import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import string
import secrets
import socket
import sys
from struct import pack, unpack

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
        print("Usage: python3 RSU_Deployment.py <RSU_ID>")
        sys.exit(0)

    index = int(sys.argv[1])
    

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("localhost", 7070))

    send_data_with_length(b"RSU", s)

    # Recv ID_TA from TA
    ID_TA_string = recv_data_with_length(s).decode()

    # Recv data from TA
    data = recv_data_with_length(s).decode()

    with open(f"RSU{index}_ID_TA.txt", "w") as f:
        f.write(ID_TA_string)
    
    with open(f"RSU{index}_data.txt", "w") as f:
        f.write(data)
    
    s.close()







if __name__ == '__main__':
    main()