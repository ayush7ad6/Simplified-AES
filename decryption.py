"""
    author: AYUSH DUBEY 2019221 
    @description: --Aes Encryption--
                    modules(built-in) -- bitstring: for bit manipulation
                                         galoid: for GF multiplication

                    methods -- formString(): create and returns a string from bit array with each block separated with a space
                               formBlocks(): returns a list from a stirng of bit array with each block separated with a space
                               encodeText(): calls formBlocks()
                               SubNib(): returns a string after substituting nibbles as per simplied aes variant
                               dSubNib(): works same as SubNib() but for decryption
                               RotNib(): returns a string after rotating rows as per simplied aes variant  
                               keyGeneration(): return a dictionary of keys generated from the secret key
                               galoisMultiply(): returns the multiplication result of lookup matrix with intermediate ciphertext computation matrix in the form of a string
                               decryption(): main computation for aes variant decryption using the aforementioned methods

"""

from bitstring import BitArray
from galois import GF

gf16 = GF(2**4)  # initialising GF(16)

encryptSBox = {'0000': '1001', '1000': '0110',
               '0001': '0100', '1001': '0010',
               '0010': '1010', '1010': '0000',
               '0011': '1011', '1011': '0011',
               '0100': '1101', '1100': '1100',
               '0101': '0001', '1101': '1110',
               '0110': '1000', '1110': '1111',
               '0111': '0101', '1111': '0111'}  # encrypt s box

# decrypt s box by invertng key and value of encrypt s box
decryptSBox = {v: k for k, v in encryptSBox.items()}


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


def encodeText(msg):

    # p = msg.encode()
    # p = BitArray(bytes=p, length=16)
    # p = p.bin
    p = msg
    return formBlocks(p)


def SubNib(nibbles):  # substituting nibbles for encryption
    nibbles = formBlocks(nibbles)  # convert to list

    for i in range(len(nibbles)):
        nibbles[i] = encryptSBox[nibbles[i]]

    return ''.join(map(str, nibbles))  # returns string


def dSubNib(nibbles):  # substituting nibble for decryption works same as SubNib()
    nibbles = formBlocks(nibbles)

    for i in range(len(nibbles)):
        # uses decrypt box instead of encrypt box
        nibbles[i] = decryptSBox[nibbles[i]]

    return ''.join(map(str, nibbles))


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

    key0 = encodeText(key0)

    keys = {}
    keys['w0'] = ''.join(map(str, key0[0:2]))
    keys['w1'] = ''.join(map(str, key0[2:4]))

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


def decryption(ciphertext, keys):
    print('Decryption Intemediate Process:')
    # p = encodeText(message)
    p = ciphertext
    print('\tCiphertext: ', formString(p))

    # # add round 2 key
    p = int(p, base=2) ^ int(keys['key2'], base=2)
    p = BitArray(uint=p, length=16).bin  # changin int to binary string
    print('\tAfter Pre-Round Transformation: ', formString(p))
    print('\tRound Key K2: ', formString(keys['key2']))

    # # shift row
    p = RotNib(p)
    print('\tAfter Round 1 InvShift Row: ', formString(p))

    # # nibble substitution
    p = dSubNib(p)
    print('\tAfter Round 1 InvSubstitute Nibbles: ', formString(p))

    # # add round 1 key
    p = int(p, base=2) ^ int(keys['key1'], base=2)
    p = BitArray(uint=p, length=16).bin  # changing int to binary string
    print('\tAfter Round 1 InvAdd Round Key: ', formString(p))
    print('\tRound Key K1: ', formString(keys['key1']))

    # mix column
    M = [[9, 2], [2, 9]]  # lookup table for decryption
    p = galoisMultiply(M, p)  # performing GF(16) multiplication
    print('\tAfter Round 1 InvMix Columns: ', formString(p))

    # # row rotation
    p = RotNib(p)
    print('\tAfter Round 2 InvShift Rows: ', formString(p))

    # nibble substitution
    p = dSubNib(p)
    print('\tAfter Round 2 InvSubstitute Nibbles: ', formString(p))

    # # add round 0 key
    p = int(p, base=2) ^ int(keys['key0'], base=2)
    p = BitArray(uint=p, length=16).bin  # changin int to binary string
    print('\tAfter Round 2 Add round key: ', formString(p))
    print('\tRound Key K0: ', formString(keys['key0']))

    plaintext = p
    print('Decrypted Plaintext: ', formString(plaintext))
    # originalMsg = frombits(plaintext)
    return plaintext


# key = 'Jõ'
# secreykey = '1010011100111011'
# message = '1101011100101000'
# # message = 'x('


# keys = keyGeneration(secreykey)

# cipherText = '0000011100111000'
# original = decryption(cipherText, keys)
# # original = frombits(original)
# print(original)
