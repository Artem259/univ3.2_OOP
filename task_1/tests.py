import unittest
from dsa.dsa import Dsa


class TestDsa(unittest.TestCase):
    def setUp(self):
        self.dsa = Dsa()

    def test_1(self):
        message = "Hello, World!"
        private_key = 0x0123456789abcdef

        message_bytes = str.encode(message, "ascii")
        public_key = self.dsa.public_key_gen(private_key)
        r, s = self.dsa.sign(message_bytes, private_key)

        self.assertTrue(self.dsa.verify(message_bytes, r, s, public_key))

        self.assertFalse(self.dsa.verify(message_bytes, r + 1, s, public_key))
        self.assertFalse(self.dsa.verify(message_bytes, r, s + 1, public_key))
        self.assertFalse(self.dsa.verify(message_bytes, r + 1, s + 1, public_key))
        self.assertFalse(self.dsa.verify(message_bytes, r, s, public_key + 1))


if __name__ == "__main__":
    unittest.main()
