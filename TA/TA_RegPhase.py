import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import string
import secrets
import socket
from struct import pack, unpack
from base64 import b16encode, b16decode
import threading


DELTA_T = 1


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
        

def bytes_XOR(byte1: bytes, byte2: bytes) -> bytes:
    """
    Calculate the XOR of two byte strings.
    """
    length = max(len(byte1), len(byte2))

    int_var = int.from_bytes(byte1, byteorder = 'big')
    int_key = int.from_bytes(byte2, byteorder = 'big')
    int_enc = int_var ^ int_key
    return int_enc.to_bytes(length, byteorder = 'big')


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
        
    

def register_vehicles(conn: socket.socket):
    # Public and private key computation
    RCvi = int(input("Enter RCvi: "))
    IDvi = generate_random_alphanumeric_string(10)

    RN = secrets.randbits(128)

    hash = hashes.Hash(hashes.SHA256())
    hash.update(IDvi.encode())
    hash.update(bin(RN)[2:].encode())
    private_key_number = hash.finalize()
    private_key_number = int.from_bytes(private_key_number, byteorder = 'big')
    private_key = ec.derive_private_key(private_key_number, ec.SECP256K1())

    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PublicFormat.SubjectPublicKeyInfo
    )

    private_key_bytes = private_key.private_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PrivateFormat.PKCS8,
        encryption_algorithm = serialization.NoEncryption()
    )

    # Calculation of Avi
    hash = hashes.Hash(hashes.SHA256())
    hash.update(bin(RCvi)[2:].encode())
    Avi = bytes_XOR(hash.finalize(), IDvi.encode())

    # Calculation of IDV*
    hash = hashes.Hash(hashes.SHA256())
    hash.update(IDvi.encode())
    hash.update(bin(RCvi)[2:].encode())
    ctime = int(time.time())
    hash.update(str(ctime).encode())
    IDV_star = hash.finalize()

    # Sending data
    send_data_with_length(Avi, conn)
    send_data_with_length(public_key_bytes, conn)
    send_data_with_length(IDV_star, conn)
    send_data_with_length(str(ctime).encode(), conn)


    # Receving data
    response = recv_data_with_length(conn).decode()
    if response == 'TIMEOUT ERROR':
        print('Timeout error')
        conn.close()
        return

    if response != '200 OK':
        print('Error in registration. IDvi* does not match.')
        conn.close()
        return

    B = recv_data_with_length(conn)
    D = recv_data_with_length(conn)
    BC = recv_data_with_length(conn)    
    rtime = int(recv_data_with_length(conn).decode())

    ctime = int(time.time())

    if ctime - rtime > DELTA_T:
        print('Timeout error')
        send_data_with_length(b'TIMEOUT ERROR', conn)
        conn.close()
        return
    
    # Calculation of AID
    hash = hashes.Hash(hashes.SHA256())
    hash.update(IDvi.encode())
    hash.update(B)
    AID = hash.finalize()

    # Calculation of C
    hash = hashes.Hash(hashes.SHA256())
    hash.update(AID)
    hash.update(bin(RCvi)[2:].encode())
    hash.update(str(rtime).encode())
    C = bytes_XOR(hash.finalize(), D)

    # Calcuation of BC
    hash = hashes.Hash(hashes.SHA256())
    hash.update(B)
    hash.update(C)
    hash.update(AID)
    hash.update(str(rtime).encode())
    BC_star = hash.finalize()


    if BC_star != BC:
        print('Error in registration. BC does not match.')
        send_data_with_length(b"BC ERROR", conn)
        conn.close()
        return
    else:
        send_data_with_length(b"200 OK", conn)
    
    with open("TA_private.pem", "rb") as f:
        TA_private_key = f.read()
    
    hash = hashes.Hash(hashes.SHA256())
    hash.update(private_key_bytes)
    hash.update(TA_private_key)
    E = bytes_XOR(hash.finalize(), C)
    E = bytes_XOR(E, B)

    # KeyRV
    hash = hashes.Hash(hashes.SHA256())
    hash.update(bytes_XOR(public_key_bytes, C))
    KeyRV = hash.finalize()

    # F
    hash1 = hashes.Hash(hashes.SHA256())
    hash1.update(private_key_bytes)
    hash1.update(TA_private_key)

    hash2 = hashes.Hash(hashes.SHA256())
    hash2.update(IDvi.encode())
    hash2.update(C)
    F = bytes_XOR(hash1.finalize(), hash2.finalize())

    with open("Vehicle_Users.txt", "a") as f:
        f.write(IDvi + "," + b16encode(AID).decode() + "," + str(private_key_number) + "," + b16encode(KeyRV).decode() + "\n")

    conn.close()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('localhost', 7080))
    print("Connected to OBU")
    
    send_data_with_length(B, s)
    send_data_with_length(E, s)
    send_data_with_length(F, s)
    send_data_with_length(public_key_bytes, s)
    s.close()

    print("Registration Successful")


def register_RSU(conn: socket.socket):

    with open("TA_ID.txt", "r") as f:
        TA_ID = f.read()

    send_data_with_length(TA_ID.encode(), conn)

    with open("Vehicle_Users.txt", "r") as f:
        data = f.read()

    send_data_with_length(data.encode(), conn)
    conn.close()





def handle_client(conn: socket.socket):

    response = recv_data_with_length(conn).decode()

    if response == 'VU':
        register_vehicles(conn)
    elif response == 'RSU':
        register_RSU(conn)
    # elif response == 'PSO':
    #     register_PSO(conn) 


def main():
    
    # Creating TA server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', 7070))
    s.listen(1)

    f = open("Vehicle_Users.txt", "w")
    f.write("ID,AID,TPR,KeyRV\n")
    f.close()

    # [t.start() for t in thread_list]
    # [t.join()  for t in thread_list]
    # Accepting connection
    try:
        while True:

            # Wait for a connection
            newsocket, fromaddr = s.accept()
            t1 = threading.Thread(target= handle_client, args=(newsocket, ))
            t1.setDaemon(True)
            t1.start()
    finally:
        newsocket.close()
        s.close()



if __name__ == '__main__':
    main()