"""
    author: AYUSH DUBEY 2019221 
    @description: --RSA Class module --
                    module(created) -
                                    func
                    rsa class for encryption, decryptiona and key generation
                    parameters: Key Generation Paramters (p,q,r)
                    variables: p,q,e (key generation parameters)
                               n (p*q)
                               phi
                               prKey (private Key)
                               pubKey (public key)
                               plaintext (message to be encrypted)
                               ciphertext (encrypted message)
                               f (flag for key parameters validation)
                    methods: Constructor: initialises key parameters, validates them and generates key if key parameters valid
                             genkey(): generates public key and private upon validation else assigns f = 1
                             validate(): checks the validity of key generation parameters  
                             encrypt(): encrypts the passes plaintext with the private key using rsa algorithm principles
                             decrypt(): decrypts the passes ciphertext with the public key using rsa algorithn principles
"""

from func import ConvertToInt, ConvertToStr, gcd, is_coprime, isPrime, is_coprime, ConvertToInt, ConvertToStr, modInverse
# importing methods from func module


class rsa:
    # constructor to assign key parameters, validate key parameter and generate private key
    def __init__(self, p, q, e):
        self.p = p
        self.q = q
        self.e = e
        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)
        self.prKey = None  # = genKey(self)
        self.pubKey = None
        self.plaintext = None
        self.ciphertext = None
        # self.validate()
        self.f = 0
        self.genKey()

    def validate(self):

        flag = True  # flage for validity TRUE assuming valid at start
        # check p
        if (self.p == self.q) or (self.q == self.e):
            print("Enter distinct values for p,q,e")
            flag = False
        if self.p != int(self.p):
            print('{} is not an integer. Please enter a valid value for p'.format(
                self.p))
            flag = False
            # return False
        if not isPrime(self.p):
            print('{} is not prime. Please enter a valid value for p'.format(
                self.p))
            flag = False
            # return False
        # check q
        if self.q != int(self.q):
            print('{} is not an integer. Please enter a valid value for q'.format(
                self.q))
            flag = False
            # return False
        if not isPrime(self.q):
            print('{} is not prime. Please enter a valid value for q'.format(
                self.q))
            flag = False
            # return False
        # check e
        if self.e != int(self.e):
            print('{} is not an integer. Please enter a valid value for e'.format(
                self.e))
            flag = False
            # return False
        if self.e >= self.phi or self.e <= 1:
            print('{} is greater than or equal to phi or less then 2'.format(self.e))
        if is_coprime(self.e, self.phi) == False:
            print('{} is a factor of phi. Enter a valid value for e'.format(
                self.e))
            flag = False
            # return False

        if flag == False:
            return False

        self.pubKey = self.e  # when valid assign public key to pubKey
        return True

    def genKey(self):
        if self.validate() == True:  # generate key when valid key parameters

            # finding the modular inverse
            d = modInverse(self.pubKey, self.phi)
            self.prKey = d
            return d
        self.f = 1

    def encrypt(self, plaintext):  # encrypting
        self.plaintext = plaintext
        # converting plaintext to digits using convertToInt() for encryption
        plaintext = ConvertToInt(plaintext)
        cipher_arr = []
        while plaintext:
            rem = plaintext % 10
            # rsa encryption formula encrypting each number corresponding to each character
            encrypt_digit = (rem**self.pubKey) % (self.n)
            cipher_arr.insert(0, encrypt_digit)
            plaintext = plaintext//10
        # genCipherText() assigns ciphertext to the class variable in string form
        self.getCiphertext(cipher_arr)
        return cipher_arr  # returns list

    def decrypt(self, ciphertext):
        plaintext = 0
        for i in ciphertext:
            # decrypting each digit in the ciphertext
            decrypt_digit = (i**self.prKey) % (self.n)
            plaintext = plaintext * 10 + decrypt_digit

        # finally converting the ciphertext (int) into string
        plaintext = ConvertToStr(plaintext)

        return plaintext

    def getCiphertext(self, ciphertextarr):
        # converting list to string
        ciphertextarr = ' '.join(map(str, ciphertextarr))
        self.ciphertext = ciphertextarr


def encrypt(plaintext, n, e):  # equivalent to def encrypt(self, plaintext): for encryption with any key without instantiating a class
    plaintext = ConvertToInt(plaintext)

    cipher_arr = []
    while plaintext:
        rem = plaintext % 10
        encrypt_digit = (rem**e) % n
        cipher_arr.insert(0, encrypt_digit)
        plaintext = plaintext//10
    getCiphertext(cipher_arr)
    return cipher_arr


# # equivalent to def getCiphertext(self, ciphertextarr): for encryption with any key without instantiating a class
def getCiphertext(ciphertextarr):
    ciphertextarr = ''.join(map(str, ciphertextarr))
    return ciphertextarr


# equivalent to def decrypt(self, ciphertext): for decryption with any key without instantiating a class
def decrypt(ciphertext, n, privateKey):
    plaintext = 0
    for i in ciphertext:

        decrypt_digit = (i**privateKey) % (n)
        plaintext = plaintext * 10 + decrypt_digit

    plaintext = ConvertToStr(plaintext)

    return plaintext


# a = rsa(23, 43, 19)


# en = a.encrypt('00000')
# n = a.n
# e = a.pubKey
# d = a.prKey

# print('d: ', d)
# print('e: ', e)
# print('phi: ', a.phi)

# print(en)
# print(a.ciphertext)


# en2 = a.decrypt(en)

# print(en2)
