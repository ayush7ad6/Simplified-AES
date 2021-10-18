from func import ConvertToInt, ConvertToStr, is_coprime, isPrime, is_coprime, ConvertToInt, ConvertToStr


class rsa:
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

        flag = True
        # check p
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

        self.pubKey = self.e
        return True

    def genKey(self):
        if self.validate() == True:

            k = 2
            d = int((k * self.phi + 1)/self.e)
            self.prKey = d
            return d
        self.f = 1

    def encrypt(self, plaintext):
        self.plaintext = plaintext
        plaintext = ConvertToInt(plaintext)
        cipher_arr = []
        while plaintext:
            rem = plaintext % 10
            encrypt_digit = (rem**self.pubKey) % (self.n)
            cipher_arr.insert(0, encrypt_digit)
            plaintext = plaintext//10
        self.getCiphertext(cipher_arr)
        return cipher_arr

    def decrypt(self, ciphertext):
        plaintext = 0
        for i in ciphertext:
            decrypt_digit = (i**self.prKey) % (self.n)
            plaintext = plaintext * 10 + decrypt_digit

        plaintext = ConvertToStr(plaintext)

        return plaintext

    def getCiphertext(self, ciphertextarr):
        ciphertextarr = ' '.join(map(str, ciphertextarr))
        self.ciphertext = ciphertextarr


def encrypt(plaintext, n, e):
    plaintext = ConvertToInt(plaintext)

    cipher_arr = []
    while plaintext:
        rem = plaintext % 10
        encrypt_digit = (rem**e) % n
        cipher_arr.insert(0, encrypt_digit)
        plaintext = plaintext//10
    getCiphertext(cipher_arr)
    return cipher_arr


def getCiphertext(ciphertextarr):
    ciphertextarr = ' '.join(map(str, ciphertextarr))
    return ciphertextarr


def decrypt(ciphertext, n, privateKey):
    plaintext = 0
    for i in ciphertext:

        decrypt_digit = (i**privateKey) % (n)
        plaintext = plaintext * 10 + decrypt_digit

    plaintext = ConvertToStr(plaintext)

    return plaintext


# a = rsa(53, 59, 3)


# en = a.encrypt('ayush dubey it is')
# n = a.n
# e = a.pubKey

# print(en)
# print(a.ciphertext)


# en2 = encrypt('ayush dubey it is', n, e)

# print(en2)
