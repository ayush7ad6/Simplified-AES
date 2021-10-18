
# import socket
from multiprocessing.connection import Listener
import pickle
import hashlib

from numpy.core.records import fromstring

from rsa import decrypt, getCiphertext, rsa
from decryption import decryption, decryption, keyGeneration, formString

# s = socket.socket()
print("\n[+] Server Socket successfully created\n")


port = 12345

# s.bind(('', port))
s = Listener(('localhost', port))
print("[+] Server Socket binded to %s\n" % (port))


# s.listen(5)

while True:
    # c, addr = s.accept()
    c = s.accept()
    print('[+] Got connection from client')

    clientMsg = c.recv()
    print(clientMsg.decode())

    while True:
        serverKey = {}
        print('Enter valid server key generation parameters:\n ')
        serverKey['p'] = int(input('p: '))
        serverKey['q'] = int(input('q: '))
        serverKey['e'] = int(input('e: '))
        serverRSA = rsa(serverKey['p'], serverKey['q'], serverKey['e'])
        if serverRSA.f == 0:
            break

    n = serverKey['p'] * serverKey['q']

    c.send(str(n).encode())
    c.send(str(serverKey['e']).encode())

    # encryptedSecretkey = c.recv(1024).decode()
    encryptedSecretkey = pickle.loads(c.recv())
    # print(encryptedSecretkey)
    # encryptedSecretkeystr = getCiphertext(encryptedSecretkey)
    # print(encryptedSecretkeystr)
    print('\n[+] Receiving Cipher text\n')
    ciphterText = (c.recv()).decode()

    SecretKey = serverRSA.decrypt(encryptedSecretkey)
    SecretKeystr = formString(SecretKey)
    print('Decrypted Secret Key: ', SecretKeystr)

    # aes decryption computation
    keys = keyGeneration(SecretKey)
    message = decryption(ciphterText, keys)
    # print('Decrypted Plaintext: ', message)

    # signautre verification
    print('\n[+] Receving client public key\n')
    clientKey = {}
    clientKey['n'] = int(c.recv().decode())
    clientKey['e'] = int(c.recv().decode())
    # clientKey = pickle.loads(c.recv(1024))
    # print('[+] Client public key: ', clientKey)

    # from io import BytesIO
    # buffer = BytesIO()
    # while chunk := c.recv():
    #     buffer.write(chunk)
    # signature = pickle.loads(buffer.getvalue())
    print('[+] Receiving Client Signature\n')
    signature = pickle.loads(c.recv())
    digest = hashlib.sha256(message.encode()).hexdigest()
    print('Message Digest: ', digest)

    verificationCode = decrypt(signature, clientKey['n'], clientKey['e'])
    print('Intermediate Verification Code: ', verificationCode)

    # verifying signature
    if verificationCode == digest:
        print()
        print("-"*30 + "Signature Verified" + "-"*30)
        print()
    else:
        print()
        print("-"*30 + "Signature Not Verified" + "-"*30)
        print()
    c.close()
    break

# 0000000000000000
