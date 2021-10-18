
import socket
import pickle
import hashlib

from rsa import decrypt, getCiphertext, rsa
from decryption import decryption, decryption, keyGeneration

s = socket.socket()
print("[+] Server Socket successfully created")


port = 12345

s.bind(('', port))
print("[+] Server Socket binded to %s" % (port))


s.listen(5)

while True:
    c, addr = s.accept()
    print('Got connection from', addr)

    clientMsg = c.recv(1024)
    print(clientMsg.decode())

    while True:
        serverKey = {}
        print('[+] Enter valid server key generation paramters: ')
        serverKey['p'] = 53  # int(input('p: '))
        serverKey['q'] = 59  # int(input('q: '))
        serverKey['e'] = 3  # int(input('e: '))
        serverRSA = rsa(serverKey['p'], serverKey['q'], serverKey['e'])
        if serverRSA.f == 0:
            break

    n = serverKey['p'] * serverKey['q']

    c.send(str(n).encode())
    c.send(str(serverKey['e']).encode())

    # encryptedSecretkey = c.recv(1024).decode()
    encryptedSecretkey = pickle.loads(c.recv(1024))
    # print(encryptedSecretkey)
    # encryptedSecretkeystr = getCiphertext(encryptedSecretkey)
    # print(encryptedSecretkeystr)

    SecretKey = serverRSA.decrypt(encryptedSecretkey)
    print('[+] Decrypted Secret Key: ', SecretKey)

    ciphterText = (c.recv(1024)).decode()
    print('[+] CipherText Received: ', ciphterText)

    # aes decryption computation
    keys = keyGeneration(SecretKey)
    message = decryption(ciphterText, keys)
    print('Decrypted Plaintext: ', message)

    # signautre verification
    print('[+] Receving client public key')
    clientKey = {}
    clientKey['n'] = int(c.recv(4).decode())
    clientKey['e'] = int(c.recv(1).decode())
    # clientKey = pickle.loads(c.recv(1024))
    print('client public key: ', clientKey)

    from io import BytesIO
    buffer = BytesIO()
    while chunk := c.recv(4096):
        buffer.write(chunk)
    signature = pickle.loads(buffer.getvalue())
    # signature = pickle.loads(c.recv(4096))
    digest = hashlib.sha256(message.encode()).hexdigest()
    print('Message Digest: ', digest)

    verificationCode = decrypt(signature, clientKey['n'], clientKey['e'])
    print('Intermediate Verification Code: ', verificationCode)

    # verifying signature
    if verificationCode == digest:
        print("Signature Verified")
    else:
        print('Signautre Not Verified')
    c.close()
    break

# 0000000000000000
