import os
import unittest
from ctpkcs11 import api, HSM


class TestUtil(unittest.TestCase):
    def setUp(self):
        self.pkcs11 = HSM(os.environ["PKCS11_MODULE"])
        self.pkcs11.open()

        # get SoftHSM major version
        self.SoftHSMversion = self.pkcs11.getInfo().libraryVersion[0]

        self.slot = self.pkcs11.getSlotList(tokenPresent=True)[0]
        self.session = self.pkcs11.openSession(self.slot, api.CKF_SERIAL_SESSION | api.CKF_RW_SESSION)
        self.session.login(os.environ["PKCS11_TOKEN_PIN"])

    def tearDown(self):
        self.session.logout()
        self.session.close()
        self.pkcs11.closeAllSessions(self.slot)
        self.pkcs11.close()
        del self.pkcs11

    def test_wrapKey(self):
        keyID = (0x01,)
        AESKeyTemplate = [
            (api.CKA_CLASS, api.CKO_SECRET_KEY),
            (api.CKA_KEY_TYPE, api.CKK_AES),
            (api.CKA_TOKEN, api.CK_TRUE),
            (api.CKA_PRIVATE, api.CK_FALSE),
            (api.CKA_ENCRYPT, api.CK_TRUE),
            (api.CKA_DECRYPT, api.CK_TRUE),
            (api.CKA_SIGN, api.CK_FALSE),
            (api.CKA_EXTRACTABLE, api.CK_TRUE),
            (api.CKA_VERIFY, api.CK_FALSE),
            (api.CKA_VALUE_LEN, 32),
            (api.CKA_LABEL, "TestAESKey"),
            (api.CKA_ID, keyID),
        ]

        if self.SoftHSMversion < 2:
            self.skipTest("generateKey() only supported by SoftHSM >= 2")

        self.wrapKey = self.session.generateKey(AESKeyTemplate)
        self.assertIsNotNone(self.wrapKey)

        keyID = (0x02,)
        # make the key extractable
        AESKeyTemplate.append((api.CKA_EXTRACTABLE, api.CK_TRUE))

        self.AESKey = self.session.generateKey(AESKeyTemplate)
        self.assertIsNotNone(self.AESKey)

        # buffer of 32 bytes 0x42
        DataIn = bytes([42] * 32)

        mechanism = api.Mechanism(api.CKM_AES_ECB)
        DataOut = self.session.encrypt(self.AESKey, DataIn, mechanism)
        # print("DataOut", DataOut)

        DataCheck = self.session.decrypt(self.AESKey, DataOut, mechanism)
        # print("DataCheck:", DataCheck)

        # check we can encrypt/decrypt with the AES key
        self.assertSequenceEqual(DataIn, DataCheck)

        # wrap using CKM_AES_KEY_WRAP
        mechanismWrap = api.Mechanism(api.CKM_AES_KEY_WRAP)
        wrapped = self.session.wrapKey(self.wrapKey, self.AESKey, mechanismWrap)
        self.assertIsNotNone(wrapped)

        # destroy the original key
        self.session.destroyObject(self.AESKey)

        # unwrap
        template = [
            (api.CKA_CLASS, api.CKO_SECRET_KEY),
            (api.CKA_KEY_TYPE, api.CKK_AES),
            (api.CKA_TOKEN, api.CK_TRUE),
            (api.CKA_PRIVATE, api.CK_FALSE),
            (api.CKA_ENCRYPT, api.CK_TRUE),
            (api.CKA_DECRYPT, api.CK_TRUE),
            (api.CKA_SIGN, api.CK_FALSE),
            (api.CKA_VERIFY, api.CK_FALSE),
        ]
        unwrapped = self.session.unwrapKey(self.wrapKey, wrapped, template, mechanismWrap)
        self.assertIsNotNone(unwrapped)

        DataCheck = self.session.decrypt(unwrapped, DataOut, mechanism)
        # print("DataCheck:", DataCheck)

        # check we can decrypt with the unwrapped AES key
        self.assertSequenceEqual(DataIn, DataCheck)

        # cleanup
        self.session.destroyObject(unwrapped)

        self.session.destroyObject(self.wrapKey)

    def test_wrapKey_OAEP(self):
        if self.SoftHSMversion < 2:
            self.skipTest("generateKey() only supported by SoftHSM >= 2")

        keyID = (0x22,)
        pubTemplate = [
            (api.CKA_CLASS, api.CKO_PUBLIC_KEY),
            (api.CKA_TOKEN, api.CK_TRUE),
            (api.CKA_PRIVATE, api.CK_FALSE),
            (api.CKA_MODULUS_BITS, 0x0400),
            (api.CKA_PUBLIC_EXPONENT, (0x01, 0x00, 0x01)),
            (api.CKA_ENCRYPT, api.CK_TRUE),
            (api.CKA_VERIFY, api.CK_TRUE),
            (api.CKA_VERIFY_RECOVER, api.CK_TRUE),
            (api.CKA_WRAP, api.CK_TRUE),
            (api.CKA_LABEL, "My Public Key"),
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
        ]

        self.pubKey, self.privKey = self.session.generateKeyPair(pubTemplate, privTemplate)
        self.assertIsNotNone(self.pubKey)
        self.assertIsNotNone(self.privKey)

        keyID = (0x02,)
        AESKeyTemplate = [
            (api.CKA_CLASS, api.CKO_SECRET_KEY),
            (api.CKA_KEY_TYPE, api.CKK_AES),
            (api.CKA_TOKEN, api.CK_TRUE),
            (api.CKA_PRIVATE, api.CK_FALSE),
            (api.CKA_ENCRYPT, api.CK_TRUE),
            (api.CKA_DECRYPT, api.CK_TRUE),
            (api.CKA_SIGN, api.CK_FALSE),
            (api.CKA_EXTRACTABLE, api.CK_TRUE),
            (api.CKA_VERIFY, api.CK_FALSE),
            (api.CKA_VALUE_LEN, 32),
            (api.CKA_LABEL, "TestAESKey"),
            (api.CKA_ID, keyID),
        ]

        # make the key extractable
        AESKeyTemplate.append((api.CKA_EXTRACTABLE, api.CK_TRUE))

        self.AESKey = self.session.generateKey(AESKeyTemplate)
        self.assertIsNotNone(self.AESKey)

        # buffer of 32 bytes 0x42
        DataIn = bytes([42] * 32)

        mechanism = api.Mechanism(api.CKM_AES_ECB)
        DataOut = self.session.encrypt(self.AESKey, DataIn, mechanism)
        # print("DataOut", DataOut)

        DataCheck = self.session.decrypt(self.AESKey, DataOut, mechanism)
        # print("DataCheck:", DataCheck)

        # check we can encrypt/decrypt with the AES key
        self.assertSequenceEqual(DataIn, DataCheck)

        # wrap using CKM_RSA_PKCS_OAEP + CKG_MGF1_SHA1
        mechanismWrap = api.RSAOAEPMechanism(api.CKM_SHA_1, api.CKG_MGF1_SHA1)
        wrapped = self.session.wrapKey(self.pubKey, self.AESKey, mechanismWrap)
        self.assertIsNotNone(wrapped)

        # destroy the original key
        self.session.destroyObject(self.AESKey)

        # unwrap
        template = [
            (api.CKA_CLASS, api.CKO_SECRET_KEY),
            (api.CKA_KEY_TYPE, api.CKK_AES),
            (api.CKA_TOKEN, api.CK_TRUE),
            (api.CKA_PRIVATE, api.CK_FALSE),
            (api.CKA_ENCRYPT, api.CK_TRUE),
            (api.CKA_DECRYPT, api.CK_TRUE),
            (api.CKA_SIGN, api.CK_FALSE),
            (api.CKA_VERIFY, api.CK_FALSE),
        ]
        unwrapped = self.session.unwrapKey(self.privKey, wrapped, template, mechanismWrap)
        self.assertIsNotNone(unwrapped)

        DataCheck = self.session.decrypt(unwrapped, DataOut, mechanism)
        # print("DataCheck:", DataCheck)

        # check we can decrypt with the unwrapped AES key
        self.assertSequenceEqual(DataIn, DataCheck)

        # cleanup
        self.session.destroyObject(unwrapped)

        self.session.destroyObject(self.pubKey)
        self.session.destroyObject(self.privKey)

    def test_wrapKey_UNWRAP_TEMPLATE(self):
        keyID = (0x01,)
        pubTemplate = [
            (api.CKA_CLASS, api.CKO_PUBLIC_KEY),
            (api.CKA_LABEL, "RSA Public Key"),
            (api.CKA_KEY_TYPE, api.CKK_RSA),
            (api.CKA_TOKEN, api.CK_TRUE),
            (api.CKA_PRIVATE, api.CK_TRUE),
            (api.CKA_VERIFY, api.CK_TRUE),
            (api.CKA_MODULUS_BITS, 2048),
            (api.CKA_PUBLIC_EXPONENT, (0x01, 0x00, 0x01)),
            (api.CKA_ID, keyID),
            (api.CKA_WRAP, api.CK_TRUE),
        ]

        unwrap_template = [
            (api.CKA_EXTRACTABLE, api.CK_FALSE),
        ]

        privTemplate = [
            (api.CKA_CLASS, api.CKO_PRIVATE_KEY),
            (api.CKA_LABEL, "RSA Private Key"),
            (api.CKA_KEY_TYPE, api.CKK_RSA),
            (api.CKA_TOKEN, api.CK_TRUE),
            (api.CKA_PRIVATE, api.CK_TRUE),
            (api.CKA_SIGN, api.CK_TRUE),
            (api.CKA_ID, keyID),
            (api.CKA_UNWRAP, api.CK_TRUE),
            (api.CKA_UNWRAP_TEMPLATE, unwrap_template),
        ]

        if self.SoftHSMversion < 2:
            self.skipTest("generateKey() only supported by SoftHSM >= 2")

        self.pubKey, self.privKey = self.session.generateKeyPair(pubTemplate, privTemplate)
        self.assertIsNotNone(self.pubKey)
        self.assertIsNotNone(self.privKey)

        keyID = (0x02,)
        AESKeyTemplate = [
            (api.CKA_CLASS, api.CKO_SECRET_KEY),
            (api.CKA_KEY_TYPE, api.CKK_AES),
            (api.CKA_TOKEN, api.CK_TRUE),
            (api.CKA_PRIVATE, api.CK_FALSE),
            (api.CKA_ENCRYPT, api.CK_TRUE),
            (api.CKA_DECRYPT, api.CK_TRUE),
            (api.CKA_SIGN, api.CK_FALSE),
            (api.CKA_EXTRACTABLE, api.CK_TRUE),
            (api.CKA_VERIFY, api.CK_FALSE),
            (api.CKA_VALUE_LEN, 32),
            (api.CKA_LABEL, "TestAESKey"),
            (api.CKA_ID, keyID),
        ]

        # make the key extractable
        AESKeyTemplate.append((api.CKA_EXTRACTABLE, api.CK_TRUE))

        self.AESKey = self.session.generateKey(AESKeyTemplate)
        self.assertIsNotNone(self.AESKey)

        # buffer of 32 bytes 0x42
        DataIn = bytes([42] * 32)

        mechanism = api.Mechanism(api.CKM_AES_ECB)
        DataOut = self.session.encrypt(self.AESKey, DataIn, mechanism)
        # print("DataOut", DataOut)

        DataCheck = self.session.decrypt(self.AESKey, DataOut, mechanism)
        # print("DataCheck:", DataCheck)

        # check we can encrypt/decrypt with the AES key
        self.assertSequenceEqual(DataIn, DataCheck)

        # wrap
        mechanismWrap = api.RSAOAEPMechanism(api.CKM_SHA_1, api.CKG_MGF1_SHA1)
        wrapped = self.session.wrapKey(self.pubKey, self.AESKey, mechanismWrap)
        self.assertIsNotNone(wrapped)

        # destroy the original key
        self.session.destroyObject(self.AESKey)

        # unwrap
        template = [
            (api.CKA_TOKEN, api.CK_TRUE),
            (api.CKA_CLASS, api.CKO_SECRET_KEY),
            (api.CKA_KEY_TYPE, api.CKK_AES),
            (api.CKA_EXTRACTABLE, api.CK_FALSE),
        ]
        unwrapped = self.session.unwrapKey(self.privKey, wrapped, template, mechanismWrap)
        self.assertIsNotNone(unwrapped)

        DataCheck = self.session.decrypt(unwrapped, DataOut, mechanism)
        # print("DataCheck:", DataCheck)

        # check we can decrypt with the unwrapped AES key
        self.assertSequenceEqual(DataIn, DataCheck)

        attributes = self.session.getAttributeValue(unwrapped, [api.CKA_EXTRACTABLE])
        self.assertSequenceEqual(attributes, [False])

        # cleanup
        self.session.destroyObject(unwrapped)

        self.session.destroyObject(self.pubKey)
        self.session.destroyObject(self.privKey)
