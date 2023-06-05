import unittest
from dsa.dsa import Dsa


class TestDsa(unittest.TestCase):
    def setUp(self):
        self.dsa = Dsa()

    def test_1(self):
        message = "Hello, World!"
        message_bytes = str.encode(message, "ascii")
        r, s = self.dsa.sign(message_bytes)

        self.assertTrue(self.dsa.verify(message_bytes, r, s))
        self.assertFalse(self.dsa.verify(message_bytes, r + 1, s))
        self.assertFalse(self.dsa.verify(message_bytes, r, s + 1))
        self.assertFalse(self.dsa.verify(message_bytes, r + 1, s + 1))


if __name__ == "__main__":
    unittest.main()
