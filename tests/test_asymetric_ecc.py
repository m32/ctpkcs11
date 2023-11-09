#!/usr/bin/env vpython3
if __name__ == '__main__':
    import run
from asn1crypto.keys import ECDomainParameters, NamedCurve
from tconfig import TestCase, api, HSMError


class TestUtil(TestCase):
    def setUp(self):
        super().setUp()
        if self.SoftHSMversion < (2, 0):
            self.skipTest("ECDSA only supported by SoftHSM >= 2")
        # Select the curve to be used for the keys
        curve = "secp256r1"

        # Setup the domain parameters, unicode conversion needed
        # for the curve string
        domain_params = ECDomainParameters(name="named", value=NamedCurve(curve))
        ec_params = domain_params.dump()

        keyID = (0x22,)
        label = "test"

        ec_public_tmpl = [
            (api.CKA_CLASS, api.CKO_PUBLIC_KEY),
            (api.CKA_PRIVATE, api.CK_FALSE),
            (api.CKA_TOKEN, api.CK_TRUE),
            (api.CKA_ENCRYPT, api.CK_TRUE),
            (api.CKA_VERIFY, api.CK_TRUE),
            (api.CKA_WRAP, api.CK_TRUE),
            (api.CKA_KEY_TYPE, api.CKK_ECDSA),
            (api.CKA_EC_PARAMS, ec_params),
            (api.CKA_LABEL, label),
            (api.CKA_ID, keyID),
        ]

        ec_priv_tmpl = [
            (api.CKA_CLASS, api.CKO_PRIVATE_KEY),
            (api.CKA_KEY_TYPE, api.CKK_ECDSA),
            (api.CKA_TOKEN, api.CK_TRUE),
            (api.CKA_SENSITIVE, api.CK_TRUE),
            (api.CKA_DECRYPT, api.CK_TRUE),
            (api.CKA_SIGN, api.CK_TRUE),
            (api.CKA_UNWRAP, api.CK_TRUE),
            (api.CKA_LABEL, label),
            (api.CKA_ID, keyID),
        ]


        (self.pubKey, self.privKey) = self.session.generateKeyPair(
            ec_public_tmpl, ec_priv_tmpl, mecha=api.MechanismECGENERATEKEYPAIR
        )
        self.assertIsNotNone(self.pubKey)
        self.assertIsNotNone(self.privKey)

        # test CK_OBJECT_HANDLE.__repr__()
        text = str(self.pubKey)
        self.assertIsNotNone(text)

    def tearDown(self):
        self.session.destroyObject(self.pubKey)
        self.session.destroyObject(self.privKey)

        super().tearDown()

    def test_sign_integer(self):
        toSign = 1234567890
        mecha = api.Mechanism(api.CKM_ECDSA, None)

        # sign/verify
        try:
            self.session.sign(self.privKey, toSign, mecha)
        except TypeError as e:
            pass

    def test_sign_bytes(self):
        toSign = b"Hello World!"
        mecha = api.Mechanism(api.CKM_ECDSA, None)

        # sign/verify
        signature = self.session.sign(self.privKey, toSign, mecha)

        result = self.session.verify(self.pubKey, toSign, signature, mecha)

        self.assertTrue(result)


if __name__ == '__main__':
    import unittest
    unittest.main()
