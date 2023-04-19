import os
import unittest
from ctpkcs11 import api, HSM, HSMError


class TestUtil(unittest.TestCase):
    def setUp(self):
        self.pkcs11 = HSM(os.environ["PKCS11_MODULE"])
        self.pkcs11.open()

        # get SoftHSM major version
        self.SoftHSMversion = self.pkcs11.getInfo().libraryVersion

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

    def test_symetric(self):
        # AES CBC with IV
        par = api.buffer(b"1234567812345678")
        mechanism = api.Mechanism(api.CKM_AES_CBC, api.addressof(par), len(par))
        self.assertIsNotNone(mechanism)

        if self.SoftHSMversion < (2,0):
            self.skipTest("generateKey() only supported by SoftHSM >= 2.0")

        keyID = (0x01,)
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
            (api.CKA_ID, keyID),
        ]

        AESKey = self.session.generateKey(AESKeyTemplate)
        self.assertIsNotNone(AESKey)

        # buffer of 32 bytes 0x00
        DataIn = bytes([0] * 32)
        # print("DataIn:", DataIn)

        # AES CBC with IV
        par = api.buffer(b"1234567812345678")
        mechanism = api.Mechanism(api.CKM_AES_CBC, api.addressof(par), len(par))

        # find the first secret key
        symKey = self.session.findObjects(
            [(api.CKA_CLASS, api.CKO_SECRET_KEY), (api.CKA_ID, keyID)]
        )[0]

        DataOut = self.session.encrypt(symKey, DataIn, mechanism)
        # print("DataOut", DataOut)

        DataCheck = self.session.decrypt(symKey, DataOut, mechanism)
        # print("DataCheck:", DataCheck)

        self.assertSequenceEqual(DataIn, DataCheck)

        # AES ECB with previous IV as Data
        mechanism = api.Mechanism(api.CKM_AES_ECB)

        # same as '1234567812345678' (the IV) but as a list
        DataECBIn = bytes([49, 50, 51, 52, 53, 54, 55, 56, 49, 50, 51, 52, 53, 54, 55, 56])
        # print("DataECBIn:", DataECBIn)
        DataECBOut = self.session.encrypt(symKey, DataECBIn, mechanism)
        # print("DataECBOut:", DataECBOut)

        DataECBCheck = self.session.decrypt(symKey, DataECBOut, mechanism)
        # print("DataECBCheck:", DataECBCheck)

        self.assertSequenceEqual(DataECBIn, DataECBCheck)

        # check the AES CBC computation is the same as the AES ECB
        # 1st block
        self.assertSequenceEqual(DataOut[:16], DataECBOut)

        # since the input is full of 0 we just pass the previous output
        DataECBOut2 = self.session.encrypt(symKey, DataECBOut, mechanism)
        # print("DataECBOut2", DataECBOut2)

        # 2nd block
        self.assertSequenceEqual(DataOut[16:], DataECBOut2)

        #
        # test CK_GCM_PARAMS
        #

        if self.SoftHSMversion <= (2,2):
            self.skipTest("CKM_AES_GCM only supported by SoftHSM > 2.2")

        AES_GCM_IV_SIZE = 12
        AES_GCM_TAG_SIZE = 16
        iv = bytes([42] * AES_GCM_IV_SIZE)
        aad = b"plaintext aad"
        tagBits = AES_GCM_TAG_SIZE * 8
        mechanism = api.AES_GCM_Mechanism(iv, aad, tagBits)

        DataOut = self.session.encrypt(symKey, DataIn, mechanism)
        # print("DataOut", DataOut)

        DataCheck = self.session.decrypt(symKey, DataOut, mechanism)
        # print("DataCheck:", DataCheck)

        self.assertSequenceEqual(DataIn, DataCheck)

        self.session.destroyObject(AESKey)
