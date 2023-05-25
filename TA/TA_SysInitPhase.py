from secrets import randbelow, randbits
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


def main():
    ctime = int(time.time())
    ID_TA = randbits(80)

    with open("TA_ID.txt", "w") as f:
        f.write(str(ID_TA))

    q = (1 << 256) - (1 << 32) - 977
    RN = randbelow(q)

    hash = hashes.Hash(hashes.SHA256())
    hash.update(str(ctime).encode())
    hash.update(bin(RN)[2:].encode())
    hash.update(bin(ID_TA)[2:].encode())
    SK_TA_bytes = hash.finalize()
    SK_TA = int.from_bytes(SK_TA_bytes, byteorder='big')

    private_key = ec.derive_private_key(SK_TA, ec.SECP256K1())
    public_key = private_key.public_key()
    
    serialized_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    serialized_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open('TA_public.pem', 'wb+') as f:
        f.write(serialized_public)

    with open('TA_private.pem', 'wb+') as f:
        f.write(serialized_private)
    
    with open('../Public/TA_public.pem', 'wb+') as f:
        f.write(serialized_public)
        

if __name__ == '__main__':
    main()