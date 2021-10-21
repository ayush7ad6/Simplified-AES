
"""
    author: AYUSH DUBEY 2019221 
    @description: --Server file --
                    modules(built-in) -- multiprocessing: sending and receiving message oriented pickles with ease
                                         pickle: to send and receive objects
                                         hashlib: to hash message using sha256
                    modules(created) -- rsa: rsa class for encryption, decryption and compute public and private keys
                                        decryption: aes variant decryption and key generation

                    inputs -- server key parameters
                    operations -- sends server public key to client (client.py)
                                  receives encyrpted secret key from client
                                  receives encyrpted plaintext(cipher text) from client
                                  decrypts ciphertext using aes variant
                                  receives client public key for signature verification
                                  computes client signature by hasing message and verifies it with the message digest
"""
# built-in modules
from multiprocessing.connection import Listener
import pickle
import hashlib
# created modules
# decrypt(): rsa decryption, getCiphertext(): returns ciphertext as string, rsa: RSA class
from src.rsa import rsa, decrypt, getCiphertext
# decryption(): aes decryption returns plaintext, keyGeneration(): aes key generation returns dict, formString(): string manipulation
from src.decryption import decryption, decryption, keyGeneration, formString


print()
print("-"*30 + "2019221 AYUSH DUBEY" + "-"*30)
print("\t\thttps://github.com/ayush7ad6/Simplified-AES")
print()


print("\n[+] Server Socket successfully created\n")


port = 12345

s = Listener(('localhost', port))  # binding to server local idle port
print("[+] Server Socket binded to %s\n" % (port))


while True:

    c = s.accept()  # establishing connection from client
    print('[+] Got connection from client')

    clientMsg = c.recv()  # receiving request from client
    print(clientMsg.decode())

    while True:
        serverKey = {}  # key generation parameters input and storing in a dict
        print('Enter valid server key generation parameters:\n ')
        serverKey['p'] = int(input('p: '))
        serverKey['q'] = int(input('q: '))
        serverKey['e'] = int(input('e: '))
        # creating RSA class instance for encryption, decryption and key validation
        serverRSA = rsa(serverKey['p'], serverKey['q'], serverKey['e'])
        if serverRSA.f == 0:  # break out of the loop if key parameter are valid
            break

    # sending server publc key
    c.send(str(serverRSA.n).encode())
    c.send(str(serverRSA.pubKey).encode())

    # receiving encrypted secret key from client
    print('\n[+] Receiving Encrypted Secret Key\n')
    encryptedSecretkey = pickle.loads(c.recv())
    # receiving cipher text
    print('[+] Receiving Cipher text\n')
    ciphterText = (c.recv()).decode()

    # decrypting received encrypted secret key with server private key
    SecretKey = decrypt(encryptedSecretkey, serverRSA.n, serverRSA.prKey)
    SecretKeystr = formString(SecretKey)
    print('Decrypted Secret Key: ', SecretKeystr)

    # aes decryption computation and key generation
    keys = keyGeneration(SecretKey)
    message = decryption(ciphterText, keys)

    # signature verification via sha256 hash and received client signature
    print('\n[+] Receving client public key\n')  # receiving client public key
    clientKey = {}
    clientKey['n'] = int(c.recv().decode())
    clientKey['e'] = int(c.recv().decode())

    print('[+] Receiving Client Signature\n')  # receiving client signature
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
