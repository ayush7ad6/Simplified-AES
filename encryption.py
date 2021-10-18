from bitstring import BitArray
from galois import GF

gf16 = GF(2**4)

encryptSBox = {'0000': '1001', '1000': '0110',
               '0001': '0100', '1001': '0010',
               '0010': '1010', '1010': '0000',
               '0011': '1011', '1011': '0011',
               '0100': '1101', '1100': '1100',
               '0101': '0001', '1101': '1110',
               '0110': '1000', '1110': '1111',
               '0111': '0101', '1111': '0111'}

decryptSBox = {v: k for k, v in encryptSBox.items()}


def tobits(s):
    result = []
    for c in s:
        bits = bin(ord(c))[2:]
        bits = '00000000'[len(bits):] + bits
        result.extend([int(b) for b in bits])
    result = "".join(str(i) for i in result)
    return result


def formString(text):
    ind = 0
    block = ""
    for i in text:
        ind = ind + 1
        if ind % 4 == 1:
            block = block + " "
        block = block + i
    return block


def formBlocks(text):
    ind = 0
    block = ""
    for i in text:
        ind = ind + 1
        if ind % 4 == 1:
            block = block + " "
        block = block + i
    return block.split()


def encodeText(msg):

    # p = msg.encode()
    # p = BitArray(bytes=p, length=16)
    # p = p.bin
    p = msg
    return formBlocks(p)


def SubNib(nibbles):
    nibbles = formBlocks(nibbles)

    for i in range(len(nibbles)):
        nibbles[i] = encryptSBox[nibbles[i]]

    return ''.join(map(str, nibbles))


def RotNib(nibbles):
    nibbles = formBlocks(nibbles)

    if len(nibbles) == 2:
        nibbles[0], nibbles[1] = nibbles[1], nibbles[0]
    elif len(nibbles) == 4:
        nibbles[1], nibbles[3] = nibbles[3], nibbles[1]

    return ''.join(map(str, nibbles))


def keyGeneration(key0):
    n0 = '10000000'
    n1 = '00110000'

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


def galoisMultiply(mat, msgList):

    #msgMat = [[msgList[0], msgList[2]], [msgList[1], msgList[3]]]
    msgList = formBlocks(msgList)
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

    s00 = BitArray(uint=s00, length=4).bin
    s10 = BitArray(uint=s10, length=4).bin
    s01 = BitArray(uint=s01, length=4).bin
    s11 = BitArray(uint=s11, length=4).bin

    # print(s00)
    # print(s10)
    # print(s01)
    # print(s11)

    return s00+s10+s01+s11


def encryption(message, keys):
    print('Cipher text intermediate computation process: ')
    # p = encodeText(message)
    p = message
    # p = tobits(message)

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
    M = [[1, 4], [4, 1]]
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
