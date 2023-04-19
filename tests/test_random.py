import os
import unittest
from ctpkcs11 import api, HSM


class TestUtil(unittest.TestCase):
    def setUp(self):
        self.pkcs11 = HSM(os.environ["PKCS11_MODULE"])
        self.pkcs11.open()

        self.slot = self.pkcs11.getSlotList(tokenPresent=True)[0]
        self.session = self.pkcs11.openSession(self.slot, api.CKF_SERIAL_SESSION)

    def tearDown(self):
        self.session.close()
        self.pkcs11.closeAllSessions(self.slot)
        self.pkcs11.close()
        del self.pkcs11

    def test_seedRandom(self):
        seed = bytes([1, 2, 3, 4])
        self.session.seedRandom(seed)

    def test_generateRandom(self):
        rnd = self.session.generateRandom()
        self.assertEqual(len(rnd), 16)

        rnd = self.session.generateRandom(32)
        self.assertEqual(len(rnd), 32)
