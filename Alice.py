from Crypto.Util import number
from BitVector import BitVector
from math import gcd
from random import randint
import socket
import pickle
import os
import time

keyDict = {1: [], 2: []}
AES_modulus = BitVector(bitstring='100011011')

Sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

InvSbox = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

Mixer = [
    [BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03")],
    [BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02")]
]

InvMixer = [
    [BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09")],
    [BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D")],
    [BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B")],
    [BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E")]
]


def keyGenerationForRSA(K):

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


def keyGenrationForAES(key):
    roundConstant = [0, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54]

    word = [[]] * 44
    for i in range(4):
        word[i] = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]

    for i in range(4, 44):
        temp = word[i - 1][:]

        if (i % 4 == 0):
            rw = rotateWord(temp)
            sw = subsWord(rw)
            rc = roundConstant[int(i / 4)]

            temp[0] = sw[0] ^ rc

        word[i] = [0] * 4
        for j in range(4):
            word[i][j] = word[i - 4][j] ^ temp[j]
    return word


def rotateWord(word):
    word[0], word[1], word[2], word[3] = word[1], word[2], word[3], word[0]
    return word


def subsWord(word):
    word[0] = Sbox[word[0]]
    word[1] = Sbox[word[1]]
    word[2] = Sbox[word[2]]
    word[3] = Sbox[word[3]]
    return word


def doSbox(matrix):
    rows = len(matrix)
    columns = len(matrix[0])

    for i in range(rows):
        for j in range(columns):
            matrix[i][j] = Sbox[matrix[i][j]]
    return matrix


def doinvSbox(matrix):
    rows = len(matrix)
    columns = len(matrix[0])

    for i in range(rows):
        for j in range(columns):
            matrix[i][j] = InvSbox[matrix[i][j]]
    return matrix


def doshiftRows(matrix):
    matrix = transpose(matrix)
    matrix[1][0], matrix[1][1], matrix[1][2], matrix[1][3] = matrix[1][1], matrix[1][2], matrix[1][3], matrix[1][0]
    matrix[2][0], matrix[2][1], matrix[2][2], matrix[2][3] = matrix[2][2], matrix[2][3], matrix[2][0], matrix[2][1]
    matrix[3][0], matrix[3][1], matrix[3][2], matrix[3][3] = matrix[3][3], matrix[3][0], matrix[3][1], matrix[3][2]
    matrix = transpose(matrix)
    return matrix


def doinvShiftRows(matrix):
    matrix = transpose(matrix)
    matrix[1][0], matrix[1][1], matrix[1][2], matrix[1][3] = matrix[1][3], matrix[1][0], matrix[1][1], matrix[1][2]
    matrix[2][0], matrix[2][1], matrix[2][2], matrix[2][3] = matrix[2][2], matrix[2][3], matrix[2][0], matrix[2][1]
    matrix[3][0], matrix[3][1], matrix[3][2], matrix[3][3] = matrix[3][1], matrix[3][2], matrix[3][3], matrix[3][0]
    matrix = transpose(matrix)
    return matrix


def domixColumns(matrix):
    matrix_b = [
        [BitVector(hexstring="00"), BitVector(hexstring="00"), BitVector(hexstring="00"), BitVector(hexstring="00")],
        [BitVector(hexstring="00"), BitVector(hexstring="00"), BitVector(hexstring="00"), BitVector(hexstring="00")],
        [BitVector(hexstring="00"), BitVector(hexstring="00"), BitVector(hexstring="00"), BitVector(hexstring="00")],
        [BitVector(hexstring="00"), BitVector(hexstring="00"), BitVector(hexstring="00"), BitVector(hexstring="00")]
    ]
    for i in range(len(matrix)):
        for j in range(len(Mixer[0])):
            for k in range(len(matrix)):
                bv1 = BitVector(intVal=matrix[i][k])
                bv2 = bv1.gf_multiply_modular(Mixer[j][k], AES_modulus, 8)
                matrix_b[j][i] ^= bv2

    for i in range(len(matrix_b)):
        for m in range(len(matrix_b)):
            matrix_b[i][m] = int(matrix_b[i][m])

    return transpose(matrix_b)


def doinvMixingcolumn(matrix):
    matrix_b = [
        [BitVector(hexstring="00"), BitVector(hexstring="00"), BitVector(hexstring="00"), BitVector(hexstring="00")],
        [BitVector(hexstring="00"), BitVector(hexstring="00"), BitVector(hexstring="00"), BitVector(hexstring="00")],
        [BitVector(hexstring="00"), BitVector(hexstring="00"), BitVector(hexstring="00"), BitVector(hexstring="00")],
        [BitVector(hexstring="00"), BitVector(hexstring="00"), BitVector(hexstring="00"), BitVector(hexstring="00")]
    ]
    for i in range(len(matrix)):
        for j in range(len(InvMixer[0])):
            for k in range(len(matrix)):
                bv1 = BitVector(intVal=matrix[i][k])
                bv2 = bv1.gf_multiply_modular(InvMixer[j][k], AES_modulus, 8)
                matrix_b[j][i] ^= bv2

    for i in range(len(matrix_b)):
        for m in range(len(matrix_b)):
            matrix_b[i][m] = int(matrix_b[i][m])

    return transpose(matrix_b)

# send key[4*4]
def doAddRoundKey(matrix, key):
    matrix_ark = []

    for i in range(4):
        row = [matrix[i][0] ^ key[i][0], matrix[i][1] ^ key[i][1], matrix[i][2] ^ key[i][2], matrix[i][3] ^ key[i][3]]
        matrix_ark.append(row)
    return matrix_ark


def EncrypteInAES(stateMatrix, key):
    r0 = key[0:4]
    r1 = key[4:8]
    r2 = key[8:12]
    r3 = key[12:16]
    r4 = key[16:20]
    r5 = key[20:24]
    r6 = key[24:28]
    r7 = key[28:32]
    r8 = key[32:36]
    r9 = key[36:40]
    r10 = key[40:44]

    rDict = {0: r0, 1: r1, 2: r2, 3: r3, 4: r4, 5: r5, 6: r6, 7: r7, 8: r8, 9: r9, 10: r10}
    stateMatrix = doAddRoundKey(stateMatrix, rDict.get(0))
    for i in range(1, 10):
        stateMatrix = doSbox(stateMatrix)
        stateMatrix = doshiftRows(stateMatrix)
        stateMatrix = domixColumns(stateMatrix)
        stateMatrix = doAddRoundKey(stateMatrix, rDict.get(i))

    # 10th round
    stateMatrix = doSbox(stateMatrix)
    stateMatrix = doshiftRows(stateMatrix)
    stateMatrix = doAddRoundKey(stateMatrix, rDict.get(10))

    return stateMatrix


def DecryptInAES(cipherText, key):
    r0 = key[0:4]
    r1 = key[4:8]
    r2 = key[8:12]
    r3 = key[12:16]
    r4 = key[16:20]
    r5 = key[20:24]
    r6 = key[24:28]
    r7 = key[28:32]
    r8 = key[32:36]
    r9 = key[36:40]
    r10 = key[40:44]

    rDict = {0: r0, 1: r1, 2: r2, 3: r3, 4: r4, 5: r5, 6: r6, 7: r7, 8: r8, 9: r9, 10: r10}

    cipherText = doAddRoundKey(cipherText, r10)

    for i in range(9, 0, -1):
        cipherText = doinvShiftRows(cipherText)
        cipherText = doinvSbox(cipherText)
        cipherText = doAddRoundKey(cipherText, rDict.get(i))
        cipherText = doinvMixingcolumn(cipherText)

    cipherText = doinvShiftRows(cipherText)
    cipherText = doinvSbox(cipherText)
    cipherText = doAddRoundKey(cipherText, rDict.get(0))

    return cipherText

def textTohexSTATE(matrix):
    rows = len(matrix)
    columns = len(matrix[0])

    for i in range(rows):
        for j in range(columns):
            matrix[i][j] = ord(matrix[i][j])
    return matrix


def textTohexKEY(word):
    l = 16 - len(word)
    for i in range(l):
        word.append(' ')
    for i in range(len(word)):
        word[i] = ord(word[i])
    return word


def convertToHex(matrix):
    rows = len(matrix)
    columns = len(matrix[0])

    for i in range(rows):
        for j in range(columns):
            matrix[i][j] = format(matrix[i][j], 'x')
    return matrix


def convertToMatrix(text):
    stateArray = []

    k = 0
    for i in range(4):
        tempArray = [0] * 4
        for j in range(4):
            tempArray[j] = text[k]
            k = k + 1
        stateArray.append(tempArray)
    return stateArray


def make16byte(text):
    if len(text) < 16:
        l = 16 - len(text)
        for i in range(l):
            text += " "
    return text


def makePlaintext(ciphertext):
    plaintext = ""
    for i in range(len(ciphertext)):
        for j in range(len(ciphertext[0])):
            plaintext += chr(ciphertext[i][j])

    plaintext = ''.join(plaintext)
    return plaintext


def transpose(matrix):
    rows = len(matrix)
    columns = len(matrix[0])

    matrix_t = []
    for j in range(columns):
        row = []
        for i in range(rows):
            row.append(matrix[i][j])
        matrix_t.append(row)

    return matrix_t


def makeByteArray(text):
    new_text = []
    for i in range(4):
        new_text.append(text[i][0])
        new_text.append(text[i][1])
        new_text.append(text[i][2])
        new_text.append(text[i][3])
    new_text = bytes(new_text)

    return new_text


# This is the Main section below.


print("Plain Text : ")
plainText = input()
plainText = make16byte(plainText)
reserveText = plainText

print("Key : ")
keyText = input()
keyText = make16byte(keyText)

print("Give the 'K' value : ")
K = int(input())

# this keyForRSA is going to RSA for encryption
keyForRSA = keyText

plainText = list(plainText)
keyText = list(keyText)


s = socket.socket()
print("Socket successfully created")

port = 12345

stateArray = convertToMatrix(plainText)
stateArray = textTohexSTATE(stateArray)

key = textTohexKEY(keyText)

# key generated for AES for main text
keysAES = keyGenrationForAES(key)


# public-private key generated for RSA
keyGenerationForRSA(K)

s.bind(('', port))

# put the socket into listening mode
s.listen(5)
print("socket is listening")

cipher = EncrypteInAES(stateArray, keysAES)


encryptedKey = EncryptInRSA(keyForRSA, keyDict.get(1))

# making a directory
path = 'D:\Cryptography\DontOpenThis'

isExist = os.path.exists(path)
if not isExist:
    os.makedirs(path)

# making the full path directory to create the file
file_name = "keys.txt"
completeName = os.path.join(path, file_name)

file = open(completeName, "w")
privateKeyE = str(keyDict.get(2)[0]) + "\n"
privateKeyN = str(keyDict.get(2)[1])
file.write(privateKeyE)
file.write(privateKeyN)
file.close()

while True:
    # Establish connection with client.
    c, addr = s.accept()
    print('Got connection from', addr)

    cipherArray = makeByteArray(cipher)

    c.send(cipherArray)
    c.send(pickle.dumps(encryptedKey))
    time.sleep(1)
    c.send(pickle.dumps(keyDict.get(1)))

    c.close()

    break
print()
time.sleep(2)
file = open("D:\Cryptography\DontOpenThis\DPT.txt","r")
line = file.read()

if(line == reserveText):
    print("Hurray !! The original text is matched.")
    print("The Original text is : ", line)
else:
    print("Oops! Something went wrong. Texts aren't matched.")
