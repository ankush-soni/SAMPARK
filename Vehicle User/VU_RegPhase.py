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

def generate_random_alphanumeric_string(length: int) -> str:
    """
    Generate a random password with at least one lowercase letter,
    one uppercase letter, and one digit.
    """

    alphabet = string.ascii_letters + string.digits
    
    while True:
        password = ''.join(secrets.choice(alphabet) for i in range(length))
        if (any(c.islower() for c in password)
            and any(c.isupper() for c in password)
            and any(c.isdigit() for c in password)):
            return password


def register(conn: socket.socket, RCvi: int, index: int):

    send_data_with_length(b"VU", conn)

    # After establishing connection
    Avi = recv_data_with_length(conn)
    public_key_bytes = recv_data_with_length(conn)
    ID_star = recv_data_with_length(conn)
    rtime = int(recv_data_with_length(conn).decode())

    public_key = serialization.load_pem_public_key(public_key_bytes)

    ctime = int(time.time())
    if(ctime - rtime > DELTA_T):
        print("Connection timeout.")
        send_data_with_length(b"TIMEOUT ERROR", conn)
        conn.close()
        exit()

    # Generating IDvi
    hash = hashes.Hash(hashes.SHA256())
    hash.update(bin(RCvi)[2:].encode())
    IDvi_check = bytes_XOR(hash.finalize(), Avi)[-10:].decode()
    
    # generating IDvi*
    hash = hashes.Hash(hashes.SHA256())
    hash.update(IDvi_check.encode())
    hash.update(bin(RCvi)[2:].encode())
    hash.update(str(rtime).encode())
    IDvi_star = hash.finalize()

    if(IDvi_star != ID_star):
        print("IDvi* does not match.")
        send_data_with_length(b"IDvi* ERROR", conn)
        conn.close()
        exit()
    else:
        send_data_with_length(b"200 OK", conn)
    

    RN = secrets.randbits(128)
    PW = generate_random_alphanumeric_string(10)


    # Generating B
    hash1 = hashes.Hash(hashes.SHA256())
    hash1.update(public_key_bytes)
    hash1.update(PW.encode())
    hash1.update(IDvi_check.encode())

    hash2 = hashes.Hash(hashes.SHA256())
    hash2.update(bin(RN)[2:].encode())
    B = bytes_XOR(hash1.finalize(), hash2.finalize())

    # AID
    hash = hashes.Hash(hashes.SHA256())
    hash.update(IDvi_check.encode())
    hash.update(B)
    AID = hash.finalize()

    # C
    hash1 = hashes.Hash(hashes.SHA256())
    hash1.update(IDvi_check.encode())
    hash1.update(PW.encode())

    hash2 = hashes.Hash(hashes.SHA256())
    hash2.update(AID)

    hash3 = hashes.Hash(hashes.SHA256())
    hash3.update(bin(RN)[2:].encode())
    hash2.update(hash3.finalize())

    C = bytes_XOR(hash1.finalize(), hash2.finalize())

    # D
    hash = hashes.Hash(hashes.SHA256())
    hash.update(AID)
    hash.update(bin(RCvi)[2:].encode())
    hash.update(str(ctime).encode())
    D = bytes_XOR(hash.finalize(), C)

    # BC
    hash = hashes.Hash(hashes.SHA256())
    hash.update(B)
    hash.update(C)
    hash.update(AID)
    hash.update(str(ctime).encode())
    BC = hash.finalize()

    # Sending to the TA
    send_data_with_length(B, conn)
    send_data_with_length(D, conn)
    send_data_with_length(BC, conn)
    send_data_with_length(str(ctime).encode(), conn)

    # Receiving from the TA
    response = recv_data_with_length(conn).decode()

    if response == '200 OK':
        print("Registration successful.")
        conn.close()
    
    else:
        print("Registration unsuccessful.")
        conn.close()
        exit()

    with open(f"Credentials/VU{index}.txt", "w") as f:
        f.write(f"ID: {IDvi_check}\n")
        f.write(f"Password: {PW}\n")

    with open(f"Credentials/VU{index}_public.pem", "wb") as f: 
        f.write(public_key_bytes)

    with open(f"../Public/VU{index}_public.pem", "wb") as f: 
        f.write(public_key_bytes)



    




def main():
    if(len(sys.argv) != 2):
        print("Usage: python3 VU_RegPhase.py <INDEX OF Vi>")
        exit()

    index = int(sys.argv[1])
    RCvi = secrets.randbits(128)
    print("RCvi:", RCvi)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.connect(("localhost", 7070))

    register(s, RCvi, index)




if __name__ == '__main__':
    main()
        