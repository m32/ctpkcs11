import os
import unittest
from ctpkcs11 import api, HSM, HSMError
from asn1crypto.keys import ECDomainParameters, NamedCurve


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

        # Select the curve to be used for the keys
        curve = u"secp256r1"

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

        if self.SoftHSMversion < 2:
            self.skipTest("ECDSA only supported by SoftHSM >= 2")

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

        self.session.logout()
        self.session.close()
        self.pkcs11.closeAllSessions(self.slot)
        self.pkcs11.close()
        del self.pkcs11

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
