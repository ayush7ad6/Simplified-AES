"""
    author: AYUSH DUBEY 2019221 
    @description: --Aes Encryption--
                    modules(built-in) -- bitstring: for bit manipulation
                                         galois: for GF multiplication

                    methods -- formString(): create and returns a string from bit array with each block separated with a space
                               formBlocks(): returns a list from a stirng of bit array with each block separated with a space
                               encodeText(): just calls formBlocks()
                               toBits(): converts string into bit array for easy manipulation
                               fromBits(): complimentary to toBits(), converts bit array into string
                               SubNib(): returns a string after substituting nibbles as per simplied aes variant
                               RotNib(): returns a string after rotating rows as per simplied aes variant  
                               keyGeneration(): return a dictionary of keys generated from the secret key
                               galoisMultiply(): returns the multiplication result of lookup matrix with intermediate ciphertext computation matrix in the form of a string
                               encryption(): main computation for aes variant encryption using the aforementioned methods

"""


from bitstring import BitArray
from galois import GF

gf16 = GF(2**4)  # initiliasing GF(16)

encryptSBox = {'0000': '1001', '1000': '0110',
               '0001': '0100', '1001': '0010',
               '0010': '1010', '1010': '0000',
               '0011': '1011', '1011': '0011',
               '0100': '1101', '1100': '1100',
               '0101': '0001', '1101': '1110',
               '0110': '1000', '1110': '1111',
               '0111': '0101', '1111': '0111'}  # encryption substitution box


def formString(text):
    ind = 0  # index for every fourth bit
    block = ""  # empty string for result
    for i in text:
        ind = ind + 1
        if ind % 4 == 1:
            block = block + " "  # inserting space after fourth bit
        block = block + i
    return block  # returning string


def formBlocks(text):
    ind = 0  # index for every fourth bit
    block = ""  # empty string for result
    for i in text:
        ind = ind + 1
        if ind % 4 == 1:
            block = block + " "  # inserting space after fourth bit
        block = block + i
    return block.split()  # returning list


def tobits(s):
    result = []
    for c in s:
        bits = bin(ord(c))[2:]
        bits = '00000000'[len(bits):] + bits
        result.extend([int(b) for b in bits])
    result = "".join(str(i) for i in result)
    return result


def encodeText(msg):

    p = msg
    return formBlocks(p)


def SubNib(nibbles):  # substituting nibbles for encryption
    nibbles = formBlocks(nibbles)  # convert to list

    for i in range(len(nibbles)):
        nibbles[i] = encryptSBox[nibbles[i]]

    return ''.join(map(str, nibbles))  # returns string


def RotNib(nibbles):  # shifting rows
    nibbles = formBlocks(nibbles)  # converts to string

    if len(nibbles) == 2:  # case for 8 bit array
        nibbles[0], nibbles[1] = nibbles[1], nibbles[0]
    elif len(nibbles) == 4:  # case for 16 bit array
        nibbles[1], nibbles[3] = nibbles[3], nibbles[1]

    return ''.join(map(str, nibbles))  # return string


def keyGeneration(key0):
    n0 = '10000000'  # round constant bit array for x3
    n1 = '00110000'  # round constant bit array for x4
    key0 = tobits(key0)  # converting string key into bit array
    key0 = encodeText(key0)  # converting list

    keys = {}
    keys['w0'] = ''.join(map(str, key0[0:2]))  # computing w0
    keys['w1'] = ''.join(map(str, key0[2:4]))  # computng w1

    # calculating w2
    keys['w2'] = int(keys['w0'], 2) ^ int(n0, 2)  # w0 XOR 1000000
    keys['w2'] = keys['w2'] ^ int(SubNib(RotNib(keys['w1'])), base=2)
    # ^ XOR SubNib(RotNib)

    # changing ^XOR int valueinto binary string
    keys['w2'] = BitArray(uint=keys['w2'], length=8).bin

    # calculating w3
    keys['w3'] = int(keys['w1'], 2) ^ int(keys['w2'], 2)
    keys['w3'] = BitArray(uint=keys['w3'], length=8).bin

    # # calculating w4
    keys['w4'] = int(keys['w2'], 2) ^ int(n1, 2)  # w2 XOR 00110000
    keys['w4'] = keys['w4'] ^ int(SubNib(RotNib(keys['w3'])), base=2)
    # ^ XOR SubNib(RotNib(w3))
    keys['w4'] = BitArray(uint=keys['w4'], length=8).bin

    # calculating w5
    keys['w5'] = int(keys['w3'], 2) ^ int(keys['w4'], 2)
    keys['w5'] = BitArray(uint=keys['w5'], length=8).bin

    # creating final keys
    finalKeys = {}
    finalKeys['key0'] = keys['w0'] + keys['w1']
    finalKeys['key1'] = keys['w2'] + keys['w3']
    finalKeys['key2'] = keys['w4'] + keys['w5']

    return finalKeys


def galoisMultiply(mat, msgList):  # mix column operation

    msgList = formBlocks(msgList)  # conver to list for easy computation
    for i in range(len(msgList)):
        msgList[i] = int(msgList[i], 2)
    s00 = int(gf16(mat[0][0]) * gf16(msgList[0])
              ) ^ int(gf16(mat[0][1]) * gf16(msgList[1]))
    s01 = int(gf16(mat[0][0]) * gf16(msgList[2])
              ) ^ int(gf16(mat[0][1]) * gf16(msgList[3]))
    s10 = int(gf16(mat[1][0]) * gf16(msgList[0])
              ) ^ int(gf16(mat[1][1]) * gf16(msgList[1]))
    s11 = int(gf16(mat[1][0]) * gf16(msgList[2])
              ) ^ int(gf16(mat[1][1]) * gf16(msgList[3]))

    # converting integer to bit array for each matrix cell
    s00 = BitArray(uint=s00, length=4).bin
    s10 = BitArray(uint=s10, length=4).bin
    s01 = BitArray(uint=s01, length=4).bin
    s11 = BitArray(uint=s11, length=4).bin

    # print(s00)
    # print(s10)
    # print(s01)
    # print(s11)

    return s00+s10+s01+s11  # concatenating each bit array string


def encryption(message, keys):
    # main aes variant encrytion using the above mentioned methods
    print('Cipher text intermediate computation process: ')
    # p = encodeText(message)
    # p = message
    p = tobits(message)  # converting string msg into bit array

    print('\tPlaintext: ', formString(p))

    # add round 0 key
    p = int(p, base=2) ^ int(keys['key0'], base=2)
    p = BitArray(uint=p, length=16).bin  # changin int to binary string
    print('\tAfter Pre-Round Transformation: ', formString(p))
    print('\tRound Key K0: ', formString(keys['key0']))

    # ROUND I

    # nibble substitution
    p = SubNib(p)
    print('\tAfter Round 1 Substitute Nibbles: ', formString(p))

    # row rotation
    p = RotNib(p)
    print('\tAfter Round 1 Shift Rows: ', formString(p))

    # mix column
    M = [[1, 4], [4, 1]]  # lookup table for encryption
    p = galoisMultiply(M, p)  # performing GF(16) multiplication
    print('\tAfter Round 1 Mix Columns: ', formString(p))

    # add round 1 key
    p = int(p, base=2) ^ int(keys['key1'], base=2)
    p = BitArray(uint=p, length=16).bin  # changing int to binary string
    print('\tAfter Round 1 Add round key: ', formString(p))
    print('\tRound Key K1: ', formString(keys['key1']))

    # ROUND 2
    # print('ROUND 2')

    # nibble substitution
    p = SubNib(p)
    print('\tAfter Round 2 Substitution Nibbles: ', formString(p))

    # shift row'
    p = RotNib(p)
    print('\tAfter Round 2 Shift Rows: ', formString(p))

    # add round 2 key
    p = int(p, base=2) ^ int(keys['key2'], base=2)
    p = BitArray(uint=p, length=16).bin
    print('\tAfter Round 2 Add round key: ', formString(p))
    print('\tRound Key K2: ', formString(keys['key2']))

    cipherText = p
    print('Ciphertext: ', formString(p))
    return cipherText


# key = 'Jõ'
# secretkey = '1010011100111011'
# message = 'ok'
# # message = 'x('


# keys = keyGeneration(secretkey)

# cipher = encryption(message, keys)
# print(cipher)
