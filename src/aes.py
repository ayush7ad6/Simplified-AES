
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

# decrypt s box by invertng key and value of encrypt s box
decryptSBox = {v: k for k, v in encryptSBox.items()}


def tobits(s):
    result = []
    for c in s:
        bits = bin(ord(c))[2:]
        bits = '00000000'[len(bits):] + bits
        result.extend([int(b) for b in bits])
    result = "".join(str(i) for i in result)
    return result


def frombits(bits):
    chars = []
    for b in range(len(bits) // 8):
        byte = bits[b*8:(b+1)*8]
        chars.append(chr(int(''.join([str(bit) for bit in byte]), 2)))
    return ''.join(chars)


def formatMsg(m):
    if len(m) % 2 != 0:
        m = m + " "
    res = []
    for a in range(0, (len(m)-1), 2):
        res.append(m[a:a+2])
    # print(res)

    for a in range(len(res)):
        res[a] = tobits(res[a])
    # print(res)

    return res


def formBlocks(text):
    ind = 0  # index for every fourth bit
    block = ""  # empty string for result
    for i in text:
        ind = ind + 1
        if ind % 4 == 1:
            block = block + " "  # inserting space after fourth bit
        block = block + i
    return block.split()  # returning list


def addKey(message, key):

    for i in range(len(message)):
        p = message[i]
        p = int(p, base=2) ^ int(key, base=2)
        p = BitArray(uint=p, length=16).bin  # changin int to binary string
        message[i] = p

    return message


def SubNib(nibbles, f=1):  # substituting nibbles for encryption

    if f == 1:
        for ind in range(len(nibbles)):
            nibbleList = formBlocks(nibbles[ind])

            for i in range(len(nibbleList)):
                nibbleList[i] = encryptSBox[nibbleList[i]]

            nibbles[ind] = ''.join(map(str, nibbleList))  # returns string
            # print(nibbles)
    else:
        nibbles = formBlocks(nibbles)  # convert to list

        for i in range(len(nibbles)):
            nibbles[i] = encryptSBox[nibbles[i]]
        nibbles = ''.join(map(str, nibbles))  # returns string
        # print(nibbles)

    return nibbles


def dSubNib(nibbles, f=1):  # substituting nibbles for decryption

    if f == 1:
        for ind in range(len(nibbles)):
            nibbleList = formBlocks(nibbles[ind])

            for i in range(len(nibbleList)):
                nibbleList[i] = decryptSBox[nibbleList[i]]

            nibbles[ind] = ''.join(map(str, nibbleList))  # returns string
            # print(nibbles)
    else:
        nibbles = formBlocks(nibbles)  # convert to list

        for i in range(len(nibbles)):
            nibbles[i] = decryptSBox[nibbles[i]]
        nibbles = ''.join(map(str, nibbles))  # returns string
        # print(nibbles)

    return nibbles


def RotNib(nibbles, f=1):  # shifting rows
    if f == 1:
        for ind in range(len(nibbles)):
            nibbleList = formBlocks(nibbles[ind])

            if len(nibbleList) == 2:  # case for 8 bit array
                nibbleList[0], nibbleList[1] = nibbleList[1], nibbleList[0]
            elif len(nibbles) == 4:  # case for 16 bit array
                nibbleList[1], nibbleList[3] = nibbleList[3], nibbleList[1]

            nibbles[ind] = ''.join(map(str, nibbleList))  # return string
        # print(nibbles)

    else:
        nibbles = formBlocks(nibbles)  # converts to string

        if len(nibbles) == 2:  # case for 8 bit array
            nibbles[0], nibbles[1] = nibbles[1], nibbles[0]
        elif len(nibbles) == 4:  # case for 16 bit array
            nibbles[1], nibbles[3] = nibbles[3], nibbles[1]

        nibbles = ''.join(map(str, nibbles))  # return string

    return nibbles


def galoisMultiply(mat, message):  # mix column operation

    for ind in range(len(message)):
        msgList = formBlocks(message[ind])

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

        message[ind] = s00+s10+s01+s11  # concatenating each bit array string
    return message


def keyGeneration(key0):
    n0 = '10000000'  # round constant bit array for x3
    n1 = '00110000'  # round constant bit array for x4
    key0 = tobits(key0)  # converting string key into bit array
    key0 = formBlocks(key0)  # converting list

    keys = {}
    keys['w0'] = ''.join(map(str, key0[0:2]))  # computing w0
    keys['w1'] = ''.join(map(str, key0[2:4]))  # computng w1

    # calculating w2
    keys['w2'] = int(keys['w0'], 2) ^ int(n0, 2)  # w0 XOR 1000000
    keys['w2'] = keys['w2'] ^ int(SubNib(RotNib(keys['w1'], 0), 0), base=2)
    # ^ XOR SubNib(RotNib)

    # changing ^XOR int valueinto binary string
    keys['w2'] = BitArray(uint=keys['w2'], length=8).bin

    # calculating w3
    keys['w3'] = int(keys['w1'], 2) ^ int(keys['w2'], 2)
    keys['w3'] = BitArray(uint=keys['w3'], length=8).bin

    # # calculating w4
    keys['w4'] = int(keys['w2'], 2) ^ int(n1, 2)  # w2 XOR 00110000
    keys['w4'] = keys['w4'] ^ int(SubNib(RotNib(keys['w3'], 0), 0), base=2)
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


def encryption(message, keys):
    keys = keyGeneration(keys)
    # main aes variant encrytion using the above mentioned methods
    print('Cipher text intermediate computation process: ')
    # p = encodeText(message)
    # p = message
    p = formatMsg(message)  # converting string msg into bit array

    print('\tPlaintext: ', ' '.join(map(str, p)))

    # add round 0 key
    p = addKey(p, keys['key0'])
    print('\tAfter Pre-Round Transformation: ', ' '.join(map(str, p)))
    print('\tRound Key K0: ', (keys['key0']))

    # ROUND I

    # nibble substitution
    p = SubNib(p)
    print('\tAfter Round 1 Substitute Nibbles: ', ' '.join(map(str, p)))

    # row rotation
    p = RotNib(p)
    print('\tAfter Round 1 Shift Rows: ', ' '.join(map(str, p)))

    # mix column
    M = [[1, 4], [4, 1]]  # lookup table for encryption
    p = galoisMultiply(M, p)  # performing GF(16) multiplication
    print('\tAfter Round 1 Mix Columns: ', ' '.join(map(str, p)))

    # add round 1 key
    p = addKey(p, keys['key1'])
    print('\tAfter Round 1 Add round key: ', ' '.join(map(str, p)))
    print('\tRound Key K1: ', (keys['key1']))

    # ROUND 2
    # print('ROUND 2')

    # nibble substitution
    p = SubNib(p)
    print('\tAfter Round 2 Substitution Nibbles: ', ' '.join(map(str, p)))

    # shift row'
    p = RotNib(p)
    print('\tAfter Round 2 Shift Rows: ', ' '.join(map(str, p)))

    # add round 2 key
    p = addKey(p, keys['key2'])
    print('\tAfter Round 2 Add round key: ', ' '.join(map(str, p)))
    print('\tRound Key K2: ', (keys['key2']))

    cipherText = p
    print('Ciphertext: ', ' '.join(map(str, p)))
    return cipherText


def decryption(ciphertext, keys):
    keys = keyGeneration(keys)
    print('Decryption Intemediate Process:')
    # p = encodeText(message)
    p = ciphertext
    print('\tCiphertext: ', ' '.join(map(str, p)))

    # # add round 2 key
    p = addKey(p, keys['key2'])
    print('\tAfter Pre-Round Transformation: ', ' '.join(map(str, p)))
    print('\tRound Key K2: ', (keys['key2']))

    # # shift row
    p = RotNib(p)
    print('\tAfter Round 1 InvShift Row: ', ' '.join(map(str, p)))

    # # nibble substitution
    p = dSubNib(p)
    print('\tAfter Round 1 InvSubstitute Nibbles: ', ' '.join(map(str, p)))

    # # add round 1 key
    p = addKey(p, keys['key1'])
    print('\tAfter Round 1 InvAdd Round Key: ', ' '.join(map(str, p)))
    print('\tRound Key K1: ', (keys['key1']))

    # mix column
    M = [[9, 2], [2, 9]]  # lookup table for decryption
    p = galoisMultiply(M, p)  # performing GF(16) multiplication
    print('\tAfter Round 1 InvMix Columns: ', ' '.join(map(str, p)))

    # # row rotation
    p = RotNib(p)
    print('\tAfter Round 2 InvShift Rows: ', ' '.join(map(str, p)))

    # nibble substitution
    p = dSubNib(p)
    print('\tAfter Round 2 InvSubstitute Nibbles: ', ' '.join(map(str, p)))

    # # add round 0 key
    p = addKey(p, keys['key0'])
    print('\tAfter Round 2 Add round key: ', ' '.join(map(str, p)))
    print('\tRound Key K0: ', (keys['key0']))

    for ind in range(len(p)):
        originalMsg = frombits(p[ind])
        p[ind] = originalMsg

    print('Decrypted Plaintext: ', ''.join(
        map(str, p)))

    p = "".join(p)
    if p[len(p)-1] == " ":
        p = p[0:len(p)-1]
      # converting into string
    return p


# a = '****daflsdkj fuck you'
# key = 'ok'
# # keys = keyGeneration(key)

# c = encryption(a, key)
# print('FINAL ciphertext: ', c)
# decryption(c, key)
