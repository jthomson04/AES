import numpy as np

from sbox import aes_sbox, reverse_aes_sbox
from pprint import pprint
import itertools
import secrets
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
    def shiftRow(data):
        
    

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
        return list(map(lambda x: map(lambda y: AES._getInverseSBoxVal(y) if inverse else AES._getSBoxVal(y), x), data))

    @staticmethod
    def encrypt(bytes):
        pass

    @staticmethod
    def decrypt(bytes):
        pass

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
        def fourAtATime(iterator):
            amount = len(iterator)
            for i in range(0, amount, 4):
                yield iterator[i: i+4]

        keys = []
        keys.append(key[0])
        keys.append(key[1])
        keys.append(key[2])
        keys.append(key[3])
        for i in range(amount-1): # gets key for each round
            getBlock(i+1, 4*(1+i))
        # keys will be an array of shape [4*amount, 4], each element is a byte
        newKeys = []
        for x in fourAtATime(keys):
            newKeys.append(x)
        return newKeys

    @staticmethod
    def generateRandomKey():
        r = [x for x in range(256)]
        def rand():
            return secrets.choice(r)
        key = []
        for i in range(4):
            key.append([rand(), rand(), rand(), rand()])
        return key
    

        

key = [[0x54, 0x68, 0x61, 0x74], [0x73, 0x20, 0x6d, 0x79], [0x20, 0x4b, 0x75, 0x6e], [0x67, 0x20, 0x46, 0x75]]
data = [[0x54, 0x77, 0x6f, 0x20], [0x4f, 0x6e, 0x65, 0x20], [0x4e, 0x69, 0x6e, 0x65], [0x20, 0x54, 0x77, 0x6f]]
keys = AES.keySchedule(key, 11) # 10 rounds plus initial key
data = AES._addRoundKey(data, keys[0])
data = AES._subBytes(data)
AES.displayKeys([data])
            
    









