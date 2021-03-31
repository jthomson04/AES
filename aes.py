import numpy as np

from sbox import aes_sbox, reverse_aes_sbox, galoisMult,  galoisField, inverseGaloisField
from pprint import pprint
import itertools
import secrets
from copy import deepcopy
import random
import string

class AES:
    
    @staticmethod
    def _getSBoxVal(val:int):
        first, last = AES._getDigits(val)
        return aes_sbox[first][last]

    @staticmethod
    def _getInverseSBoxVal(val:int):
        first, last = AES._getDigits(val)
        return reverse_aes_sbox[first][last]

    @staticmethod
    def _addRoundKey(data, key):
        assert len(data) == 4 and len(data[0]) == 4
        assert len(key) == 4 and len(key[0]) == 4
        return list(np.array(data) ^ np.array(key))

    @staticmethod
    def _shiftRows(data, inverse=False):
        data = list(np.transpose(data))
        data[1] = AES.shiftArr(data[1], 1 if inverse else -1)
        data[2] = AES.shiftArr(data[2], 2 if inverse else -2)
        data[3] = AES.shiftArr(data[3], 3 if inverse else -3)
        return list(np.transpose(data))
    
    
    
    
    @staticmethod
    def _mixColumns(cols, inverse=False):
        def mixColumn(col, index, inverse=False):
            field = inverseGaloisField if inverse else galoisField
            newCol = []
            for i in range(len(col)):
                yeet = galoisMult[field[i][0]][col[0]]
                yeet2 = galoisMult[field[i][1]][col[1]]
                yeet3 = galoisMult[field[i][2]][col[2]]
                yeet4 = galoisMult[field[i][3]][col[3]]
                newCol.append(galoisMult[field[i][0]][col[0]] ^ galoisMult[field[i][1]][col[1]] ^ galoisMult[field[i][2]][col[2]] ^ galoisMult[field[i][3]][col[3]])
            return newCol
        for i in range(4):
            cols[i] = mixColumn(cols[i], i, inverse=inverse)
        return cols

    @staticmethod
    def _getDigits(val:int):
        if len(hex(val)) == 3:
            first = 0
            last = int(hex(val)[2], 16)
        else:
            first = int(hex(val)[2], 16)
            last = int(hex(val)[3], 16)
        return first, last

    @staticmethod
    def _subBytes(data, inverse=False):
        return list(map(lambda x: list(map(lambda y: AES._getInverseSBoxVal(y) if inverse else AES._getSBoxVal(y), x)), data))

    @staticmethod
    def encrypt(string, key=None):
        def encrypt16Bytes(bytes):
            data = AES._addRoundKey(bytes, roundKeys[0])
            for i in range(1, 10):
            
                data = AES._subBytes(data)
                data = AES._shiftRows(data)
                data = AES._mixColumns(data)
                data = AES._addRoundKey(data, roundKeys[i])
            data = AES._subBytes(data)
            data = AES._shiftRows(data)
            data = AES._addRoundKey(data, roundKeys[10])
            return data


        if key is None:
            key = AES.generateRandomKey()
        roundKeys = AES.keySchedule(key, 11)
        rawData = list(bytearray(string, encoding='iso-8859-1'))
        #rawData += [0 for _ in range(rawData % 16)]
        bytes = AES._preprocess(rawData)
        encrypted = []
        for b in bytes:
            encrypted.append(encrypt16Bytes(b))
       
        return AES.bytesToString(list(np.array(encrypted).flatten())), key


    @staticmethod
    def decrypt(string, key):
        def decrypt16Bytes(data):
            data = AES._addRoundKey(data, roundKeys[10])

            for i in range(9, 0, -1):
                
                data = AES._shiftRows(data, inverse=True)
                data = AES._subBytes(data, inverse=True)
                data = AES._addRoundKey(data, roundKeys[i])
                data = AES._mixColumns(data, inverse=True)
            data = AES._shiftRows(data, inverse=True)
            data = AES._subBytes(data, inverse=True)
            data = AES._addRoundKey(data, roundKeys[0])
            return data


        # String is bytes converted to string using utf-32
        data = list(bytearray(string, encoding='iso-8859-1'))
        
        bytes = AES._preprocess(data)
        roundKeys = AES.keySchedule(key, 11)
        decrypted = []
        for b in bytes:
            decrypted.append(decrypt16Bytes(b))

        return AES.bytesToString(list(np.array(decrypted).flatten()), removeNulls=True)
        
    

    @staticmethod
    def _preprocess(data):
        padding = (16-len(data)%16)%16
        data += [0 for _ in range(padding)]
        iterator = AES.fourAtATime(data)
        newData = []
        for section in range(int(len(data)/16)):
            segment = []
            for _ in range(4):
                segment.append(iterator.__next__())
            newData.append(segment)
        return newData
            

    @staticmethod
    def shiftArr(row, amount:int):
        # positive amount denotes shift right
        amount = (abs(amount) % len(row))*(1 if amount > 0 else -1)
        
        newArr = []
        for x in range(len(row)):
            newArr.append(0)
        for i in range(len(row)):
            newIndex = i + amount
            if newIndex > len(row)-1:
                newIndex %= len(row)
            elif newIndex < 0:
                newIndex = len(row)+newIndex
            newArr[newIndex] = row[i]
        return newArr

    @staticmethod
    def displayKeys(keys):
        for key in keys:
            assert(len(key) == 4)
            x = list(itertools.chain.from_iterable(key))
            print(list(map(lambda j: j if len(j)== 2 else "0" + j, map(lambda i: hex(i)[2:], x))))

    @staticmethod
    def keySchedule(key, amount:int):
        #key is array of words (32 bits)
        rcons = [
            None,
            [0x01, 0, 0, 0],
            [0x02, 0, 0, 0],
            [0x04, 0, 0, 0],
            [0x08, 0, 0, 0],
            [0x10, 0, 0, 0],
            [0x20, 0, 0, 0],
            [0x40, 0, 0, 0],
            [0x80, 0, 0, 0],
            [0x1b, 0, 0, 0],
            [0x36, 0, 0, 0],
            [0x6c, 0, 0, 0],
            [0xd8, 0, 0, 0],
            [0xab, 0, 0, 0],
            [0x4d, 0, 0, 0],
            [0x9a, 0, 0, 0],
            [0x2f, 0, 0, 0],
        ]
        def RotWord(words):
            return AES.shiftArr(words, -1)
        def SubWord(words):
            return list(map(lambda x: AES._getSBoxVal(x), words))
        
        def elementWiseXOR(*args):
            amount = len(args)
            newArr = []
            for i in range(len(args[0])):
                val = args[0][i]
                for j in range(1, len(args)):
                    val = val ^ args[j][i]
                newArr.append(val)
            return newArr
        def g(words, round):
            words = RotWord(words)
            words = SubWord(words)
            words = elementWiseXOR(words, rcons[round])
            return words
        
        def getBlock(round, index):
            #keys.append(elementWiseXOR(keys[0], g(keys[3], 1)))
            keys.append(elementWiseXOR(keys[index-4], g(keys[index-1], round)))
            index+=1
            for i in range(3):
                keys.append(elementWiseXOR(keys[index+i-1], keys[index+i-4]))
    

        keys = []
        keys.append(key[0])
        keys.append(key[1])
        keys.append(key[2])
        keys.append(key[3])
        for i in range(amount-1): # gets key for each round
            getBlock(i+1, 4*(1+i))
        # keys will be an array of shape [4*amount, 4], each element is a byte
        newKeys = []
        for x in AES.fourAtATime(keys):
            newKeys.append(x)
        return newKeys

    @staticmethod
    def fourAtATime(iterator):
        amount = len(iterator)
        for i in range(0, amount, 4):
            yield iterator[i: i+4]

    @staticmethod
    def generateRandomKey():
        r = [x for x in range(256)]
        def rand():
            return secrets.choice(r)
        key = []
        for i in range(4):
            key.append([rand(), rand(), rand(), rand()])
        return key


    
    @staticmethod
    def bytesToString(data, removeNulls=False):
        
        
        s = ""
        '''for i in data:
            c = chr(i)
            if not (removeNulls and c == "\x00"):
                s += c'''
        data = list(bytearray(data))
        l = len(data)
        
        for i in range(l):
            c = chr(data[i])
            if not (removeNulls and c == "\x00"):
                s += c
        return s
        #return x.decode(encoding='iso-8859-1')

    


if __name__ == "__main__":
    #key = [[0x54, 0x68, 0x61, 0x74], [0x73, 0x20, 0x6d, 0x79], [0x20, 0x4b, 0x75, 0x6e], [0x67, 0x20, 0x46, 0x75]]
    data = [[0x54, 0x77, 0x6f, 0x20], [0x4f, 0x6e, 0x65, 0x20], [0x4e, 0x69, 0x6e, 0x65], [0x20, 0x54, 0x77, 0x6f]]
    '''for i in range(1000):
        encoded, key = AES.encrypt("JOHN is verycool")
        AES.displayKeys([encoded])
        cryptex = AES.bytesToString(encoded)
        
        data = AES.decrypt(cryptex, key)
        data = AES.bytesToString(data, forPrinting=True)
        assert(data == "JOHN is verycool")'''
        #x = AES.fourAtATime([1, 1, 1, 1, 1, 1, 1, 1, 1, 1])
    print(AES.decrypt("JOHN is verycool", data))






            
    









