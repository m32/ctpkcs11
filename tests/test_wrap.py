#!/usr/bin/env vpython3
if __name__ == '__main__':
    import run
from tconfig import TestCase, api, HSMError


class TestUtil(TestCase):
    def test_wrapKey(self):
        self.wrapKey = self.createAESKey(0x01)
        self.assertIsNotNone(self.wrapKey)

        self.AESKey = self.createAESKey(0x02, extractable=True)
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
        self.pubKey, self.privKey = self.createRSAKey(0x1)
        self.assertIsNotNone(self.pubKey)
        self.assertIsNotNone(self.privKey)

        self.AESKey = self.createAESKey(0x02, extractable=True)
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
        keyID = 0x01
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

        if self.SoftHSMversion < (2, 0):
            self.skipTest("generateKey() only supported by SoftHSM >= 2")

        self.pubKey, self.privKey = self.session.generateKeyPair(pubTemplate, privTemplate)
        self.assertIsNotNone(self.pubKey)
        self.assertIsNotNone(self.privKey)

        self.AESKey = self.createAESKey(0x02, extractable=True)
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


if __name__ == '__main__':
    import unittest
    unittest.main()
