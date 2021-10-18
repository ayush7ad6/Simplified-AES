import socket
import pickle
import hashlib

from numpy.lib.function_base import _SIGNATURE
from numpy.testing._private.utils import clear_and_catch_warnings

from rsa import encrypt, getCiphertext, rsa
from encryption import encryption, keyGeneration


s = socket.socket()

print("[+] Client Socket successfully created")

serverPort = 12345


s.connect(('127.0.0.1', serverPort))
s.setblocking(1)

while True:
    message = '1111111111111111'  # input('Plaintext: ')

    secretKey = '0000000000000000'  # input('Secret Key: ')

    while True:
        clientKey = {}
        print('[+] Enter valid client key generation paramters: ')
        clientKey['p'] = 53  # int(input('p: '))
        clientKey['q'] = 59  # int(input('q: '))
        clientKey['e'] = 3  # int(input('e: '))

        clientRSA = rsa(clientKey['p'], clientKey['q'], clientKey['e'])
        if(clientRSA.f == 0):
            break

    msg1 = '\n[+] Client requesting server public key'
    s.send(bytes(msg1, 'utf-8'))

    serverKey = {}
    serverKey['n'] = int(s.recv(1024).decode())
    serverKey['e'] = int(s.recv(1024).decode())

    print('[+] Server key received {}'.format(serverKey))

    # encrypting and sending secretkey
    encryptedSecretKey = encrypt(secretKey, serverKey['n'], serverKey['e'])
    #encryptedSecretKey = getCiphertext(encryptedSecretKey)
    data = pickle.dumps(encryptedSecretKey)

    encryptedSecretkeystr = getCiphertext(encryptedSecretKey)
    # print(encryptedSecretkeystr)
    print('[+] Encrypted Secrety Key: ', encryptedSecretkeystr)
    s.send(data)

    # aes computation
    keys = keyGeneration(secretKey)
    ciphterText = encryption(message, keys)
    print("Ciphertext: ", ciphterText)

    print("[+] Sending ciphertext")
    s.send(ciphterText.encode())

    # generating signature
    digest = hashlib.sha256(message.encode()).hexdigest()
    print('Digest: ', digest)

    signature = encrypt(digest, clientRSA.n, clientRSA.prKey)
    signaturestr = getCiphertext(signature)
    print('Digital Signature: ', signaturestr)

    print('[+] Sending Client Public Key')
    n = int(clientRSA.n)
    e = int(clientRSA.pubKey)
    s.send(str(n).encode())
    s.send(str(e).encode())
    # ck = {'n': clientRSA.n, 'e': clientRSA.pubKey}
    # data = pickle.dumps(ck)
    # s.send(data)

    print('[+] Sending Client Signature')
    # print('signature original: ', signature)
    # signature = ['123', '123']
    data = pickle.dumps(signature)
    s.send(data)
    break
