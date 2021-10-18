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
