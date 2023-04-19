import os
import unittest
from ctpkcs11 import api, HSM, HSMError


class TestUtil(unittest.TestCase):
    def test_CKM(self):
        self.assertEqual(api.CKM_RSA_PKCS_KEY_PAIR_GEN, 0x00000000)
        self.assertEqual(
            api.CKM[api.CKM_RSA_PKCS_KEY_PAIR_GEN], "CKM_RSA_PKCS_KEY_PAIR_GEN"
        )

        self.assertEqual(api.CKM_VENDOR_DEFINED, 0x80000000)

    def test_CKR(self):
        self.assertEqual(api.CKR_VENDOR_DEFINED, 0x80000000)

    def test_CKH(self):
        self.assertEqual(api.CKH_USER_INTERFACE, 3)
        self.assertEqual(api.CKH['CKH_USER_INTERFACE'], 3)
