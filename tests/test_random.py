#!/usr/bin/env vpython3
if __name__ == '__main__':
    import run
from tconfig import TestCase, api, HSMError


class TestUtil(TestCase):
    withlogin = False

    def test_seedRandom(self):
        seed = bytes([1, 2, 3, 4])
        self.session.seedRandom(seed)

    def test_generateRandom(self):
        rnd = self.session.generateRandom()
        self.assertEqual(len(rnd), 16)

        rnd = self.session.generateRandom(32)
        self.assertEqual(len(rnd), 32)



if __name__ == '__main__':
    import unittest
    unittest.main()
