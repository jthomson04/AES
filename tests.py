import unittest
from aes import AES
import string
import random
import os

class TestAES(unittest.TestCase):
    def test_SingleByteEncryptDecrypt(self):
        for i in range(100):
            text = ''.join([random.choice(string.ascii_letters) for _ in range(16)])
            encoded, key = AES.encrypt(text, multiThreaded=False)
            data = AES.decrypt(encoded, key, multiThreaded=False)
            self.assertEqual(data, text)

    def test_multiByteEncryptDecrypt(self):
        for i in range(100):
            text = ''.join([random.choice(string.ascii_letters) for _ in range(random.randint(3, 10)*16)])
            encoded, key = AES.encrypt(text, multiThreaded=False)
            data = AES.decrypt(encoded, key, multiThreaded=False)
            self.assertEqual(data, text)

    def test_PartialByteEncryptDecrypt(self):
        for i in range(100):
            text = ''.join([random.choice(string.ascii_letters) for _ in range(random.randint(20, 100))])
            encoded, key = AES.encrypt(text, multiThreaded=False)
            data = AES.decrypt(encoded, key, multiThreaded=False)
            self.assertEqual(data, text)
    
    def test_longString(self):
        for i in range(10):
            text = ''.join([random.choice(string.ascii_letters) for _ in range(random.randint(2000, 4000))])
            encoded, key = AES.encrypt(text, multiThreaded=False)
            data = AES.decrypt(encoded, key, multiThreaded=False)
            self.assertEqual(data, text)
        
    


    
        



unittest.main()