"""
    author: AYUSH DUBEY 2019221 
    @description: --Function module --
                    modules(built-in) -- math

                    methods -- isPrime(): returns True if a number is prime False otherwise
                               gcd(): return the greatest common divisor of an integer
                               is_coprime(): return True if two integers are co-prime i.e. their gcg is 1
                               modInverse(): returns the modular inverse of two positive numbers
                               ConvertToInt(): converts a string to its integer equivalent using each character's ASCII value
                               CovertToStr(): takes the integer output of ConvertToInt() as an input to compute the string fed in ConvertToInt()
"""

import math


def isPrime(n):
    if n == 2:
        return True
    root = int(math.sqrt(n))
    for x in range(2, root):
        if n % x == 0:
            return False
    return True


def gcd(p, q):
    # Create the gcd of two positive integers.
    while q != 0:
        p, q = q, p % q
    return p


def is_coprime(x, y):
    return gcd(x, y) == 1


def modInverse(a, m):
    m0 = m
    y = 0
    x = 1

    if (m == 1):
        return 0

    while (a > 1):

        # q is quotient
        q = a // m

        t = m

        # m is remainder now, process
        # same as Euclid's algo
        m = a % m
        a = t
        t = y

        # Update x and y
        y = x - q * y
        x = t

    # Make x positive
    if (x < 0):
        x = x + m0

    return x


def ConvertToStr(num):
    st = ""
    while (num != 0):
        temp = num % 256
        st += chr(temp)
        chr(temp)
        num = num - temp
        num = num // 256
    st = st[::-1]
    return st


def ConvertToInt(message):
    grd = 1
    num = 0
    message = str(message)
    message = message[::-1]
    for i in range(0, len(message), +1):
        num = num + ord(message[i]) * grd
        grd *= 256
    return num


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
