import unittest
from dsa.dsa import Dsa


class TestDsa(unittest.TestCase):
    def setUp(self):
        self.dsa = Dsa()

    def test_1(self):
        message = "Hello, World!"
        message_bytes = str.encode(message, "ascii")
        _, public, (r, s) = self.dsa.sign(message_bytes)

        self.assertTrue(self.dsa.verify(message_bytes, r, s, public))
        self.assertFalse(self.dsa.verify(message_bytes, r + 1, s, public))
        self.assertFalse(self.dsa.verify(message_bytes, r, s + 1, public))
        self.assertFalse(self.dsa.verify(message_bytes, r + 1, s + 1, public))

        self.assertFalse(self.dsa.verify(message_bytes, r, s, public + 1))


if __name__ == "__main__":
    unittest.main()
