#!/usr/bin/env vpython3
if __name__ == '__main__':
    import run
from tconfig import TestCase, api, HSMError


class TestUtil(TestCase):
    def test_gost(self):
        if self.SoftHSMversion < (2, 0):
            self.skipTest("generateKeyPair() only supported by SoftHSM >= 2")

        # values from SoftHSMv2
        param_a = bytes((0x06, 0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01))
        param_b = bytes((0x06, 0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x1E, 0x01))

        keyID = (0x23,)
        pubTemplate = [
            (api.CKA_TOKEN, api.CK_TRUE),
            (api.CKA_PRIVATE, api.CK_FALSE),
            (api.CKA_ENCRYPT, api.CK_TRUE),
            (api.CKA_VERIFY, api.CK_TRUE),
            (api.CKA_WRAP, api.CK_TRUE),
            (api.CKA_LABEL, "My Public Key"),
            (api.CKA_ID, keyID),
            (api.CKA_GOSTR3410_PARAMS, param_a),
            (api.CKA_GOSTR3411_PARAMS, param_b),
        ]

        privTemplate = [
            (api.CKA_TOKEN, api.CK_TRUE),
            (api.CKA_PRIVATE, api.CK_TRUE),
            (api.CKA_DECRYPT, api.CK_TRUE),
            (api.CKA_SIGN, api.CK_TRUE),
            (api.CKA_UNWRAP, api.CK_TRUE),
            (api.CKA_ID, keyID),
        ]

        # test generate gost key pair
        gen_mechanism = api.Mechanism(api.CKM_GOSTR3410_KEY_PAIR_GEN, None)
        try:
            (self.pubKey, self.privKey) = self.session.generateKeyPair(
                pubTemplate, privTemplate, gen_mechanism
            )
        except HSMError as e:
            if e.rc == api.CKR_MECHANISM_INVALID:
                self.skipTest("GOST not supported by SoftHSMv2 on Windows?")
            else:
                raise

        self.assertIsNotNone(self.pubKey)
        self.assertIsNotNone(self.privKey)

        # test sign GOSTR3410_WITH_GOSTR3411
        toSign = "Hello world"
        mecha = api.Mechanism(api.CKM_GOSTR3410_WITH_GOSTR3411, None)

        # sign/verify
        signature = self.session.sign(self.privKey, toSign, mecha)

        result = self.session.verify(self.pubKey, toSign, signature, mecha)
        self.assertTrue(result)

        # test CK_OBJECT_HANDLE.__repr__()
        text = str(self.pubKey)
        self.assertIsNotNone(text)

        self.session.destroyObject(self.pubKey)
        self.session.destroyObject(self.privKey)



if __name__ == '__main__':
    import unittest
    unittest.main()
