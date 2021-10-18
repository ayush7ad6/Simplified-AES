# import socket
from multiprocessing.connection import Client, Listener
import pickle
import hashlib

from numpy.lib.function_base import _SIGNATURE
from numpy.testing._private.utils import clear_and_catch_warnings

from rsa import encrypt, getCiphertext, rsa
from encryption import encryption, keyGeneration


# s = socket.socket()

print("\n[+] Client Socket successfully created\n")

serverPort = 12345


# s.connect(('127.0.0.1', serverPort))
# s.setblocking(1)
s = Client(('localhost', serverPort))


while True:
    message = input('Plaintext: ')

    secretKey = input('Secret Key: ')

    while True:
        clientKey = {}
        print('\nEnter valid client key generation parameters: \n')
        clientKey['p'] = int(input('p: '))
        clientKey['q'] = int(input('q: '))
        clientKey['e'] = int(input('e: '))

        clientRSA = rsa(clientKey['p'], clientKey['q'], clientKey['e'])
        if(clientRSA.f == 0):
            break

    msg1 = '\n[+] Client requesting server public key\n'
    s.send(bytes(msg1, 'utf-8'))

    print('\n[+] Receiving Server Public Key\n')
    serverKey = {}
    serverKey['n'] = int(s.recv().decode())
    serverKey['e'] = int(s.recv().decode())

    # print('[+] Server key received {}\n'.format(serverKey))

    # encrypting and sending secretkey
    encryptedSecretKey = encrypt(secretKey, serverKey['n'], serverKey['e'])
    #encryptedSecretKey = getCiphertext(encryptedSecretKey)
    data = pickle.dumps(encryptedSecretKey)

    encryptedSecretkeystr = getCiphertext(encryptedSecretKey)
    # print(encryptedSecretkeystr)
    print('Encrypted Secrety Key: ', encryptedSecretkeystr)
    s.send(data)

    # aes computation
    keys = keyGeneration(secretKey)
    ciphterText = encryption(message, keys)
    # print("\nCiphertext: ", ciphterText)

    print("\n[+] Sending ciphertext\n")
    s.send(ciphterText.encode())

    # generating signature
    digest = hashlib.sha256(message.encode()).hexdigest()
    print('Digest: ', digest)

    signature = encrypt(digest, clientRSA.n, clientRSA.prKey)
    signaturestr = getCiphertext(signature)
    print('Digital Signature: ', signaturestr)

    print('\n[+] Sending Client Public Key')
    n = int(clientRSA.n)
    e = int(clientRSA.pubKey)
    s.send(str(n).encode())
    s.send(str(e).encode())
    # ck = {'n': clientRSA.n, 'e': clientRSA.pubKey}
    # data = pickle.dumps(ck)
    # s.send(data)

    print('\n[+] Sending Client Signature\n')
    # print('signature original: ', signature)
    # signature = ['123', '123']
    data = pickle.dumps(signature)
    s.send(data)
    break
