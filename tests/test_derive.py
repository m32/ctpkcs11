import os
import unittest
from ctpkcs11 import api, HSM, HSMError
from asn1crypto.keys import ECDomainParameters, NamedCurve

class TestUtil(unittest.TestCase):
    def setUp(self):
        self.pkcs11 = HSM(os.environ["PKCS11_MODULE"])
        self.pkcs11.open()

        # get SoftHSM major version
        info = self.pkcs11.getInfo()
        self.SoftHSMversion = info.libraryVersion[0]
        self.manufacturer = info.manufacturerID

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
        self.ecParams = domain_params.dump()

        keyID = (0x01,)
        baseKeyPubTemplate = [
            (api.CKA_CLASS, api.CKO_PUBLIC_KEY),
            (api.CKA_PRIVATE, api.CK_FALSE),
            (api.CKA_TOKEN, api.CK_TRUE),
            (api.CKA_ENCRYPT, api.CK_TRUE),
            (api.CKA_VERIFY, api.CK_TRUE),
            (api.CKA_WRAP, api.CK_TRUE),
            (api.CKA_KEY_TYPE, api.CKK_ECDSA),
            (api.CKA_EC_PARAMS, self.ecParams),
            (api.CKA_LABEL, "TestBaseKeyP256"),
            (api.CKA_ID, keyID),
        ]
        baseKeyPvtTemplate = [
            (api.CKA_CLASS, api.CKO_PRIVATE_KEY),
            (api.CKA_KEY_TYPE, api.CKK_ECDSA),
            (api.CKA_TOKEN, api.CK_TRUE),
            (api.CKA_SENSITIVE, api.CK_TRUE),
            (api.CKA_PRIVATE, api.CK_FALSE),
            (api.CKA_DECRYPT, api.CK_TRUE),
            (api.CKA_SIGN, api.CK_TRUE),
            (api.CKA_UNWRAP, api.CK_TRUE),
            (api.CKA_LABEL, "TestBaseKeyP256"),
            (api.CKA_ID, keyID),
            (api.CKA_DERIVE, api.CK_TRUE),
        ]
        mechanism = api.Mechanism(api.CKM_EC_KEY_PAIR_GEN, None)
        self.baseEcPubKey, self.baseEcPvtKey = self.session.generateKeyPair(baseKeyPubTemplate, baseKeyPvtTemplate, mechanism)
        self.assertIsNotNone(self.baseEcPubKey)
        self.assertIsNotNone(self.baseEcPvtKey)

    def tearDown(self):
        self.session.destroyObject(self.baseEcPubKey)
        self.session.destroyObject(self.baseEcPvtKey)

        self.session.logout()
        self.session.close()
        self.pkcs11.closeAllSessions(self.slot)
        self.pkcs11.close()
        del self.pkcs11

    def test_deriveKey_ECDH1_DERIVE(self):
        if self.SoftHSMversion < 2:
            self.skipTest("generateKeyPair() only supported by SoftHSM >= 2")

        keyID = (0x11,)
        pubTemplate = [
            (api.CKA_CLASS, api.CKO_PUBLIC_KEY),
            (api.CKA_PRIVATE, api.CK_FALSE),
            (api.CKA_TOKEN, api.CK_FALSE),
            (api.CKA_ENCRYPT, api.CK_TRUE),
            (api.CKA_VERIFY, api.CK_TRUE),
            (api.CKA_WRAP, api.CK_TRUE),
            (api.CKA_KEY_TYPE, api.CKK_ECDSA),
            (api.CKA_EC_PARAMS, self.ecParams),
            (api.CKA_LABEL, "testKeyP256"),
            (api.CKA_ID, keyID),
        ]
        pvtTemplate = [
            (api.CKA_CLASS, api.CKO_PRIVATE_KEY),
            (api.CKA_KEY_TYPE, api.CKK_ECDSA),
            (api.CKA_TOKEN, api.CK_FALSE),
            (api.CKA_SENSITIVE, api.CK_TRUE),
            (api.CKA_PRIVATE, api.CK_TRUE),
            (api.CKA_DECRYPT, api.CK_TRUE),
            (api.CKA_SIGN, api.CK_TRUE),
            (api.CKA_UNWRAP, api.CK_TRUE),
            (api.CKA_LABEL, "testKeyP256"),
            (api.CKA_ID, keyID),
            (api.CKA_DERIVE, api.CK_TRUE),
        ]
        mechanism = api.Mechanism(api.CKM_EC_KEY_PAIR_GEN, None)
        pubKey, pvtKey = self.session.generateKeyPair(pubTemplate, pvtTemplate, mechanism)
        self.assertIsNotNone(pubKey)
        self.assertIsNotNone(pvtKey)

        keyID = (0x22,)
        derivedAESKeyTemplate = [
            (api.CKA_CLASS, api.CKO_SECRET_KEY),
            (api.CKA_KEY_TYPE, api.CKK_AES),
            (api.CKA_TOKEN, api.CK_FALSE),
            (api.CKA_SENSITIVE, api.CK_TRUE),
            (api.CKA_PRIVATE, api.CK_TRUE),
            (api.CKA_ENCRYPT, api.CK_TRUE),
            (api.CKA_DECRYPT, api.CK_TRUE),
            (api.CKA_SIGN, api.CK_FALSE),
            (api.CKA_EXTRACTABLE, api.CK_TRUE),
            (api.CKA_VERIFY, api.CK_FALSE),
            (api.CKA_VALUE_LEN, 24),
            (api.CKA_LABEL, "derivedAESKey"),
            (api.CKA_ID, keyID),
        ]

        # derive key 1 : self.basePvtKey + pubKey
        attrs = self.session.getAttributeValue(pubKey, [api.CKA_EC_POINT], True)
        mechanism = api.ECDH1_DERIVE_Mechanism(attrs[0])
        derivedKey = self.session.deriveKey(self.baseEcPvtKey, derivedAESKeyTemplate, mechanism)
        self.assertIsNotNone(derivedKey)

        # derive key 2 : pvtKey + self.basePubKey
        attrs = self.session.getAttributeValue(self.baseEcPubKey, [api.CKA_EC_POINT], True)
        mechanism = api.ECDH1_DERIVE_Mechanism(bytes(attrs[0]))
        derivedKey2 = self.session.deriveKey(pvtKey, derivedAESKeyTemplate, mechanism)
        self.assertIsNotNone(derivedKey2)

        DataIn = "Sample data to test ecdh1 derive".encode("utf-8")
        par = api.buffer(b"1234567812345678")
        mechanism = api.Mechanism(api.CKM_AES_CBC, api.addressof(par), len(par))
        DataOut = self.session.encrypt(derivedKey, DataIn, mechanism)
        DataCheck = self.session.decrypt(derivedKey2, DataOut, mechanism)

        # match check values
        self.assertSequenceEqual(DataIn, DataCheck)

        # cleanup
        self.session.destroyObject(derivedKey)
        self.session.destroyObject(derivedKey2)
        self.session.destroyObject(pubKey)
        self.session.destroyObject(pvtKey)
