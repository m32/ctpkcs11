#!/usr/bin/env vpython3
if __name__ == '__main__':
    import run
from tconfig import TestCase, api, HSMError


class TestUtil(TestCase):
    def setUp(self):
        super().setUp()

        # get SoftHSM major version
        info = self.pkcs11.getInfo()
        self.manufacturer = info.manufacturerID

        self.pubKey, self.privKey = self.createRSAKey(0x22)
        self.assertIsNotNone(self.pubKey)
        self.assertIsNotNone(self.privKey)

    def tearDown(self):
        self.session.destroyObject(self.pubKey)
        self.session.destroyObject(self.privKey)

        super().tearDown()

    def test_sign_integer(self):
        toSign = 1234567890
        mecha = api.Mechanism(api.CKM_SHA1_RSA_PKCS, None)

        # sign/verify
        try:
            self.session.sign(self.privKey, toSign, mecha)
        except TypeError:
            pass

    def test_sign_PKCS(self):
        toSign = b"Hello world"
        mecha = api.Mechanism(api.CKM_SHA1_RSA_PKCS, None)

        # sign/verify
        signature = self.session.sign(self.privKey, toSign, mecha)

        result = self.session.verify(self.pubKey, toSign, signature, mecha)

        self.assertTrue(result)

    def test_sign_PKCS_SHA256(self):
        toSign = b"Hello world"
        mecha = api.Mechanism(api.CKM_SHA256_RSA_PKCS, None)

        # sign/verify
        signature = self.session.sign(self.privKey, toSign, mecha)

        result = self.session.verify(self.pubKey, toSign, signature, mecha)

        self.assertTrue(result)

    def test_sign_X509(self):
        toSign = b"Hello world"
        mecha = api.Mechanism(api.CKM_RSA_X_509, None)

        if self.SoftHSMversion < (2, 0):
            self.skipTest("RSA X.509 only supported by SoftHSM >= 2")

        # sign/verify
        signature = self.session.sign(self.privKey, toSign, mecha)

        result = self.session.verify(self.pubKey, toSign, signature, mecha)

        self.assertTrue(result)

    def test_encrypt_PKCS(self):
        # encrypt/decrypt using CMK_RSA_PKCS (default)
        dataIn = b"Hello world"
        encrypted = self.session.encrypt(self.pubKey, dataIn)
        decrypted = self.session.decrypt(self.privKey, encrypted)

        self.assertEqual(dataIn, decrypted)

    def test_encrypt_X509(self):
        if self.SoftHSMversion < (2, 0):
            self.skipTest("RSA X.509 only supported by SoftHSM >= 2")

        # encrypt/decrypt using CKM_RSA_X_509
        dataIn = b"Hello world!"
        mecha = api.Mechanism(api.CKM_RSA_X_509, None)
        encrypted = self.session.encrypt(self.pubKey, dataIn, mecha=mecha)
        decrypted = self.session.decrypt(self.privKey, encrypted, mecha=mecha)

        # remove padding NUL bytes
        padding_length = 0
        for e in decrypted:
            if e != 0:
                break
            padding_length += 1
        decrypted = decrypted[padding_length:]

        self.assertEqual(dataIn, decrypted)

    def test_RSA_OAEP(self):
        if self.SoftHSMversion < (2, 0):
            self.skipTest("RSA OAEP only supported by SoftHSM >= 2")

        # RSA OAEP
        plainText = b"A test string"

        mech = api.RSAOAEPMechanism(api.CKM_SHA_1, api.CKG_MGF1_SHA1)
        cipherText = self.session.encrypt(self.pubKey, plainText, mech)
        decrypted = self.session.decrypt(self.privKey, cipherText, mech)

        self.assertEqual(plainText, decrypted)

    def test_RSA_OAEPwithAAD(self):
        # AAD is "Additional Authentication Data"
        # (pSourceData of CK_RSA_PKCS_OAEP_PARAMS struct)
        if self.SoftHSMversion < (2, 0):
            self.skipTest("RSA OAEP only supported by SoftHSM >= 2")

        if self.manufacturer.startswith("SoftHSM"):
            # SoftHSM indicates in syslog:
            #  "SoftHSM.cpp(12412): pSourceData must be NULL"
            # and returns CKR_ARGUMENTS_BAD
            self.skipTest("'AAD' not (yet) supported.")

        plainText = b"A test string"

        # RSA OAEP
        aad = "sample aad".encode("utf-8")
        mech = api.RSAOAEPMechanism(api.CKM_SHA_1, api.CKG_MGF1_SHA1, aad)
        cipherText = self.session.encrypt(self.pubKey, plainText, mech)
        decrypted = self.session.decrypt(self.privKey, cipherText, mech)

        self.assertEqual(plainText, decrypted)

    def test_RSA_PSS_SHA1(self):
        if self.SoftHSMversion < (2, 0):
            self.skipTest("RSA PSS only supported by SoftHSM >= 2")

        # RSA PSS
        toSign = b"test_RSA_sign_PSS SHA1"

        mech = api.RSA_PSS_Mechanism(
            api.CKM_SHA1_RSA_PKCS_PSS,
            api.CKM_SHA_1,
            api.CKG_MGF1_SHA1,
            20 # size of SHA1 result
        )
        signature = self.session.sign(self.privKey, toSign, mech)
        result = self.session.verify(self.pubKey, toSign, signature, mech)

        self.assertTrue(result)

    def test_RSA_PSS_SHA256(self):
        if self.SoftHSMversion < (2, 0):
            self.skipTest("RSA PSS only supported by SoftHSM >= 2")

        # RSA PSS
        toSign = b"test_RSA_sign_PSS SHA256"

        mech = api.RSA_PSS_Mechanism(
            api.CKM_SHA256_RSA_PKCS_PSS,
            api.CKM_SHA256,
            api.CKG_MGF1_SHA256,
            32 # size of SHA256 result
        )
        signature = self.session.sign(self.privKey, toSign, mech)
        result = self.session.verify(self.pubKey, toSign, signature, mech)

        self.assertTrue(result)

    def test_pubKey(self):
        # test CK_OBJECT_HANDLE.__repr__()
        text = str(self.pubKey)
        self.assertIsNotNone(text)


if __name__ == '__main__':
    import unittest
    unittest.main()
