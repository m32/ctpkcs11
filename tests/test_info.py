import os
import unittest
from ctpkcs11 import api, HSM, HSMError


class TestUtil(unittest.TestCase):
    def setUp(self):
        self.pkcs11 = HSM(os.environ["PKCS11_MODULE"])
        self.pkcs11.open()

        self.slot = self.pkcs11.getSlotList(tokenPresent=True)[0]
        self.manufacturerIDs = ("SoftHSM", "SoftHSM project")

    def tearDown(self):
        self.pkcs11.close()
        del self.pkcs11

    def test_getInfo(self):
        info = self.pkcs11.getInfo()

        # check the CK_UTF8CHAR to string convertion
        self.assertEqual(info.manufacturerID, "SoftHSM")
        self.assertEqual(info.libraryDescription, "Implementation of PKCS11")

        text = str(info)
        self.assertIsNotNone(text)

    def test_getSlotInfo(self):
        info = self.pkcs11.getSlotInfo(self.slot)

        self.assertIn(info.manufacturerID, self.manufacturerIDs)

        text = str(info)
        self.assertIsNotNone(text)

    def test_getTokenInfo(self):
        info = self.pkcs11.getTokenInfo(self.slot)

        self.assertIn(info.manufacturerID, self.manufacturerIDs)

        text = str(info)
        self.assertIsNotNone(text)

    def test_getSessionInfo(self):
        self.session = self.pkcs11.openSession(self.slot, api.CKF_SERIAL_SESSION)
        info = self.session.getSessionInfo()
        text = str(info)
        self.assertIsNotNone(text)
        self.session.close()

    def test_getMechanismList(self):
        mechanisms = self.pkcs11.getMechanismList(self.slot)
        text = str(mechanisms)
        self.assertIsNotNone(text)

        # info for the first mechanism
        info = self.pkcs11.getMechanismInfo(self.slot, mechanisms[0])
        text = str(info)
        self.assertIsNotNone(text)
