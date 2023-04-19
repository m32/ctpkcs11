import os
import unittest
from ctpkcs11 import api, HSM, HSMError


class TestUtil(unittest.TestCase):
    def setUp(self):
        self.pkcs11 = HSM(os.environ["PKCS11_MODULE"])
        self.pkcs11.open()

        self.slot = self.pkcs11.getSlotList(tokenPresent=True)[0]
        self.session = self.pkcs11.openSession(
            self.slot, api.CKF_SERIAL_SESSION | api.CKF_RW_SESSION
        )

    def tearDown(self):
        self.session.close()
        self.pkcs11.closeAllSessions(self.slot)
        self.pkcs11.close()
        del self.pkcs11

    def test_login(self):
        self.session.login("1234")
        self.session.logout()

    def test_wrong(self):
        with self.assertRaises(HSMError) as cm:
            self.session.login("wrong PIN")

        the_exception = cm.exception
        self.assertEqual(the_exception.rc, api.CKR_PIN_INCORRECT)
        #self.assertEqual(str(the_exception), "CKR_PIN_INCORRECT (0x000000A0)")

    def test_ckbytelist(self):
        pin = b"1234"
        self.session.login(pin)
        self.session.logout()

    def test_binary(self):
        with self.assertRaises(HSMError) as cm:
            pin = bytes([1, 2, 3, 4])
            self.session.login(pin)

        the_exception = cm.exception
        self.assertEqual(the_exception.rc, api.CKR_PIN_INCORRECT)
        #self.assertEqual(str(the_exception), "CKR_PIN_INCORRECT (0x000000A0)")

    def test_null(self):
        # SoftHSM2 does not support pinpad (pin = NULL)
        with self.assertRaises(TypeError) as cm:
            self.session.login(None)

        #the_exception = cm.exception
        #self.assertEqual(the_exception.rc, api.CKR_ARGUMENTS_BAD)
        #self.assertEqual(str(the_exception), "CKR_ARGUMENTS_BAD (0x00000007)")
