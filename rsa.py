from Crypto.Util import number
from BitVector import BitVector
from math import gcd
from random import randint
import timeit
keyDict = {1: [], 2: []}


def keygenerationForRSA(K):

    k = int(K/2)
    p = number.getPrime(k)
    q = number.getPrime(k)
    n = p*q
    phiN = (p-1)*(q-1)

    while True:
        i = randint(2, phiN)
        if gcd(i, phiN) == 1:
            e = i
            break

    E = BitVector(intVal=e)
    phiN = BitVector(intVal=phiN)

    d = int(E.multiplicative_inverse(phiN))

    keyDict[1] = [e, n]
    keyDict[2] = [d, n]


def EncryptInRSA(text, keyDict):
    text = list(text)
    cipher = []
    e = keyDict[0]
    n = keyDict[1]
    for i in range(len(text)):
        cipher.append(pow(ord(text[i]), e, n))
    return cipher


def DecryptinRSA(cipher, keyDict):
    text = []
    d = keyDict[0]
    n = keyDict[1]
    for i in range(len(cipher)):
        text.append(pow(cipher[i], d, n))
        text[i] = chr(text[i])
    return ''.join(text)


print("Enter your text : ")
message = input()

report_time = [["K", "Key-Generation", "Encryption", "Decryption"]]

K = [16, 32, 64, 128]

for i in K:

    st1 = timeit.default_timer()
    keygenerationForRSA(i)
    et1 = timeit.default_timer()
    timeForKeyGenerate = et1 - st1

    st2 = timeit.default_timer()
    cipher = EncryptInRSA(message, keyDict.get(1))
    et2 = timeit.default_timer()
    timeForEncrypt = et2 - st2

    st3 = timeit.default_timer()
    text = DecryptinRSA(cipher, keyDict.get(2))
    et3 = timeit.default_timer()
    timeForDecrypt = et3 - st3

    print("For K =", i, "the Decrypted text is : ", text)

    report_time.append([i, timeForKeyGenerate, timeForEncrypt, timeForDecrypt])

print()
for i in range(5):
    print(report_time[i])
