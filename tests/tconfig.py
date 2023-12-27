import os
import unittest
from ctpkcs11 import api, HSM, HSMError

class TestCase(unittest.TestCase):
    withlogin = True

    def setUp(self):
        self.pkcs11 = HSM(os.environ["PKCS11_MODULE"])
        self.pkcs11.open()

        # get SoftHSM major version
        self.SoftHSMversion = self.pkcs11.getInfo().libraryVersion

        self.slot = self.pkcs11.getSlotList(tokenPresent=True)[0]
        self.session = self.pkcs11.openSession(self.slot, api.CKF_SERIAL_SESSION | api.CKF_RW_SESSION)
        if self.withlogin:
            self.session.login(os.environ["PKCS11_TOKEN_PIN"])

    def tearDown(self):
        if self.withlogin:
            self.session.logout()
        self.session.close()
        self.pkcs11.closeAllSessions(self.slot)
        self.pkcs11.close()
        del self.pkcs11

    def xskipTest(self, why):
        print(why)
        super().skipTest(why)

    def createRSAKey(self, keyID, bits=0x0400):
        if self.SoftHSMversion < (2, 0):
            self.skipTest("generateKey() only supported by SoftHSM >= 2")

        pubTemplate = [
            (api.CKA_CLASS, api.CKO_PUBLIC_KEY),
            (api.CKA_TOKEN, api.CK_TRUE),
            (api.CKA_PRIVATE, api.CK_FALSE),
            (api.CKA_MODULUS_BITS, bits),
            (api.CKA_PUBLIC_EXPONENT, (0x01, 0x00, 0x01)),
            (api.CKA_ENCRYPT, api.CK_TRUE),
            (api.CKA_VERIFY, api.CK_TRUE),
            (api.CKA_VERIFY_RECOVER, api.CK_TRUE),
            (api.CKA_WRAP, api.CK_TRUE),
            (api.CKA_LABEL, "RSA Public Key"),
            (api.CKA_ID, keyID),
        ]

        privTemplate = [
            (api.CKA_CLASS, api.CKO_PRIVATE_KEY),
            (api.CKA_TOKEN, api.CK_TRUE),
            (api.CKA_PRIVATE, api.CK_TRUE),
            (api.CKA_DECRYPT, api.CK_TRUE),
            (api.CKA_SIGN, api.CK_TRUE),
            (api.CKA_SIGN_RECOVER, api.CK_TRUE),
            (api.CKA_UNWRAP, api.CK_TRUE),
            (api.CKA_ID, keyID),
            (api.CKA_LABEL, "RSA Private Key"),
        ]

        return self.session.generateKeyPair(pubTemplate, privTemplate)

    def createAESKey(self, keyID, bits=256, extractable=False):
        if self.SoftHSMversion < (2, 0):
            self.skipTest("generateKey() only supported by SoftHSM >= 2")

        AESKeyTemplate = [
            (api.CKA_CLASS, api.CKO_SECRET_KEY),
            (api.CKA_KEY_TYPE, api.CKK_AES),
            (api.CKA_TOKEN, api.CK_TRUE),
            (api.CKA_PRIVATE, api.CK_FALSE),
            (api.CKA_ENCRYPT, api.CK_TRUE),
            (api.CKA_DECRYPT, api.CK_TRUE),
            (api.CKA_SIGN, api.CK_FALSE),
            (api.CKA_VERIFY, api.CK_FALSE),
            (api.CKA_VALUE_LEN, bits // 8),
            (api.CKA_LABEL, "AES Key"),
            (api.CKA_ID, keyID),
            (api.CKA_EXTRACTABLE, api.CK_TRUE if extractable else api.CK_FALSE),
        ]

        return self.session.generateKey(AESKeyTemplate)
