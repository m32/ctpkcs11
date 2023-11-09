#!/usr/bin/env vpython3
if __name__ == '__main__':
    import run
import sys
from tconfig import TestCase, api, HSMError


class TestUtil(TestCase):
    withlogin = False

    def test_initPin(self):
        # use admin pin
        self.session.login("123456", user_type=api.CKU_SO)
        # change PIN
        self.session.initPin("4321")
        self.session.logout()

        # check new PIN
        self.session.login("4321")
        self.session.logout()

        # reset to old PIN
        self.session.login("123456", user_type=api.CKU_SO)
        self.session.initPin("1234")
        self.session.logout()

        # check old PIN
        self.session.login("1234")
        self.session.logout()

    def test_setPin(self):
        self.session.login("1234")

        # change PIN
        self.session.setPin("1234", "4321")
        self.session.logout()

        # test new PIN
        self.session.login("4321")

        # revert to old PIN
        self.session.setPin("4321", "1234")
        self.session.logout()

    def test_initToken(self):
        self.session.close()
        self.pkcs11.closeAllSessions(self.slot)

        # use admin PIN
        self.pkcs11.initToken(self.slot, "123456", "my label")
        self.session = self.pkcs11.openSession(
            self.slot, api.CKF_SERIAL_SESSION | api.CKF_RW_SESSION
        )
        self.session.login("123456", user_type=api.CKU_SO)
        # set user PIN
        self.session.initPin("1234")
        self.session.logout()

    def test_initToken_utf8(self):

        # for Python version ≥ 3 only
        import sys

        if sys.version_info[0] < 3:
            return

        self.pkcs11.closeAllSessions(self.slot)

        # Create a label using UTF-8
        label = "abcéàç"
        # padding with spaces up to 32 _bytes_ (not characters)
        #label += " " * (32 - len(label.encode("utf-8")))

        # use admin PIN
        self.pkcs11.initToken(self.slot, "123456", label)
        self.session = self.pkcs11.openSession(
            self.slot, api.CKF_SERIAL_SESSION | api.CKF_RW_SESSION
        )
        self.session.login("123456", user_type=api.CKU_SO)
        # set user PIN
        self.session.initPin("1234")

        token_info = self.pkcs11.getTokenInfo(self.slot)
        self.assertEqual(token_info.label, label)

        self.session.logout()



if __name__ == '__main__':
    import unittest
    unittest.main()
