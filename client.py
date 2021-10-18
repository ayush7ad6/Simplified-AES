"""
    author: AYUSH DUBEY 2019221 
    @description: --Client file --
                    modules(built-in) -- multiprocessing: sending and receiving message oriented pickles with ease
                                         pickle: to send and receive objects
                                         hashlib: to hash message using sha256
                    modules(created) -- rsa: rsa class for encryption, decryption and compute public and private keys
                                        encryption: aes variant encryption and key generation

                    inputs -- message, secret key, client key parameters
                    operations -- requests and receives server public key from server (server.py)
                                  encrypts secret key and sends it to the server
                                  encrypts plaintext and sends ciphertext to the server
                                  sends client public key to the server
                                  computes client signature by hasing message and sends it to the server
"""
#built in modules
from multiprocessing.connection import Client, Listener
import pickle
import hashlib

# created modules
# encrypt(): for encryption returns ciphertext, getCiphertext(): to get ciphertext string, rsa: RSA class
from rsa import encrypt, getCiphertext, rsa
# encryption(): for aes encryption, keyGeneration(): for key generation
from encryption import encryption, keyGeneration


print()
print("-"*30 + "2019221 AYUSH DUBEY" + "-"*30)
print()


print("\n[+] Client Socket successfully created\n")

serverPort = 12345

# connecting with the server remote remote
s = Client(('localhost', serverPort))


while True:
    message = input('Plaintext(8 bits only): ')  # taking message input

    secretKey = input('Secret Key(8 bits only): ')  # taking secret key input

    while True:
        clientKey = {}  # client key parameters input and storing in dict
        print('\nEnter valid client key generation parameters: \n')
        clientKey['p'] = int(input('p: '))
        clientKey['q'] = int(input('q: '))
        clientKey['e'] = int(input('e: '))

        # creating RSA instance for key parameters validation and public/private key generation
        clientRSA = rsa(clientKey['p'], clientKey['q'], clientKey['e'])
        if(clientRSA.f == 0):  # break out of the loop if key parameter are valid
            break

    # sending request to send server public key
    msg1 = '\n[+] Client requesting server public key\n'
    s.send(bytes(msg1, 'utf-8'))

    # receiving server public key and storing in a dict
    print('\n[+] Receiving Server Public Key\n')
    serverKey = {}
    serverKey['n'] = int(s.recv().decode())
    serverKey['e'] = int(s.recv().decode())

    # encrypting and sending secretkey using server public key
    encryptedSecretKey = encrypt(secretKey, serverKey['n'], serverKey['e'])
    print('[+] Sending encrypted Secrety Key\n')
    data = pickle.dumps(encryptedSecretKey)

    encryptedSecretkeystr = getCiphertext(encryptedSecretKey)
    print('Encrypted Secrety Key: ', encryptedSecretkeystr)
    s.send(data)

    # aes variant key generationa and computation
    keys = keyGeneration(secretKey)
    ciphterText = encryption(message, keys)

    print("\n[+] Sending ciphertext\n")  # sending computed ciphertext
    s.send(ciphterText.encode())

    # generating signature
    # using sha256 as a one-way hash
    digest = hashlib.sha256(message.encode()).hexdigest()
    print('Digest: ', digest)

    signature = encrypt(digest, clientRSA.n, clientRSA.prKey)
    signaturestr = getCiphertext(signature)
    print('Digital Signature: ', signaturestr)

    print('\n[+] Sending Client Public Key')     # sending client pubilc key
    n = int(clientRSA.n)
    e = int(clientRSA.pubKey)
    s.send(str(n).encode())
    s.send(str(e).encode())

    print('\n[+] Sending Client Signature\n')  # sending client signature

    data = pickle.dumps(signature)
    s.send(data)
    break
