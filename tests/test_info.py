#!/usr/bin/env vpython3
if __name__ == '__main__':
    import run
from tconfig import TestCase, api, HSMError


class TestUtil(TestCase):
    withlogin = False

    def setUp(self):
        super().setUp()
        self.manufacturerIDs = ("SoftHSM", "SoftHSM project")

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
        session = self.pkcs11.openSession(self.slot, api.CKF_SERIAL_SESSION)
        info = session.getSessionInfo()
        text = str(info)
        self.assertIsNotNone(text)
        session.close()

    def test_getMechanismList(self):
        mechanisms = self.pkcs11.getMechanismList(self.slot)
        text = str(mechanisms)
        self.assertIsNotNone(text)

        # info for the first mechanism
        info = self.pkcs11.getMechanismInfo(self.slot, mechanisms[0])
        text = str(info)
        self.assertIsNotNone(text)



if __name__ == '__main__':
    import unittest
    unittest.main()
