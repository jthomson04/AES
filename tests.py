import unittest
from aes import AES
import string
import random

class TestAES(unittest.TestCase):
    def test_SingleByteEncryptDecrypt(self):
        for i in range(1000):
            text = ''.join([random.choice(string.ascii_letters) for _ in range(16)])
            encoded, key = AES.encrypt(text)
            cryptex = AES.bytesToString(encoded)
            
            data = AES.decrypt(cryptex, key)
            data = AES.bytesToString(data, forPrinting=True)
            self.assertEqual(data, text)

unittest.main()