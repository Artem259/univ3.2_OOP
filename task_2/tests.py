import random
import unittest
from aes import aes


class TestAes(unittest.TestCase):
    def test_1(self):
        attempts = 100
        max_v = 0xffffffffffffffff
        for i in range(1, attempts + 1):
            in_data = random.randint(0, max_v)
            key = random.randint(0, max_v)

            encrypted = aes.encrypt(in_data, key)
            out_data = aes.decrypt(encrypted, key)

            self.assertEqual(in_data, out_data)
