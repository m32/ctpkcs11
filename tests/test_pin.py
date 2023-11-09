#!/usr/bin/env vpython3
if __name__ == '__main__':
    import run
from tconfig import TestCase, api, HSMError


class TestUtil(TestCase):
    withlogin = False

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



if __name__ == '__main__':
    import unittest
    unittest.main()
