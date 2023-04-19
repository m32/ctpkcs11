import os
import unittest
from ctpkcs11 import api, HSM, HSMError


class TestUtil(unittest.TestCase):
    def setUp(self):
        self.pkcs11 = HSM(os.environ["PKCS11_MODULE"])
        self.pkcs11.open()

        # get SoftHSM major version
        self.SoftHSMversion = self.pkcs11.getInfo().libraryVersion[0]

        self.slot = self.pkcs11.getSlotList(tokenPresent=True)[0]

        self.session = self.pkcs11.openSession(
            self.slot, api.CKF_SERIAL_SESSION | api.CKF_RW_SESSION
        )
        self.session.login("1234")

    def tearDown(self):
        self.session.logout()
        self.session.close()
        self.pkcs11.closeAllSessions(self.slot)
        self.pkcs11.close()
        del self.pkcs11

    def test_Objects(self):
        if self.SoftHSMversion < 2:
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
            (api.CKA_VALUE_LEN, 32),
            (api.CKA_LABEL, "TestAESKey"),
            (api.CKA_ID, (0x01,)),
        ]

        # generate AES key
        AESKey = self.session.generateKey(AESKeyTemplate)
        self.assertIsNotNone(AESKey)

        # find the first secret key
        symKey = self.session.findObjects(
            [(api.CKA_CLASS, api.CKO_SECRET_KEY)]
        )[0]

        # test object handle
        text = str(symKey)
        self.assertIsNotNone(text)

        # test createObject()
        template = [(api.CKA_CLASS, api.CKO_DATA), (api.CKA_LABEL, "data")]
        handle = self.session.createObject(template)
        self.assertIsNotNone(handle)

        self.session.destroyObject(handle)

        # test getAttributeValue

        # attributes as define by AESKeyTemplate
        all_attributes = [
            api.CKA_CLASS,
            api.CKA_KEY_TYPE,
            api.CKA_TOKEN,
            api.CKA_LABEL,
            api.CKA_ID,
        ]

        values = self.session.getAttributeValue(AESKey, all_attributes)
        self.assertEqual(
            values,
            [
                api.CKO_SECRET_KEY,
                api.CKK_AES,
                api.CK_TRUE,
                "TestAESKey",
                bytes((0x01,)),
            ],
        )

        self.session.destroyObject(AESKey)

        template = [(api.CKA_HW_FEATURE_TYPE, api.CKH_USER_INTERFACE)]
        o = self.session.findObjects(template)
