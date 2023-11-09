#!/usr/bin/env vpython3
if __name__ == '__main__':
    import run
import io
from tconfig import TestCase, api, HSMError


class TestUtil(TestCase):

    keyID = (0x01,)
    keyLABEL = "TestAESKey"

    def setupKey(self):
        AESKeyTemplate = [
            (api.CKA_CLASS, api.CKO_SECRET_KEY),
            (api.CKA_KEY_TYPE, api.CKK_AES),
            (api.CKA_TOKEN, api.CK_TRUE),
            (api.CKA_PRIVATE, api.CK_FALSE),
            (api.CKA_ENCRYPT, api.CK_TRUE),
            (api.CKA_DECRYPT, api.CK_TRUE),
            (api.CKA_SIGN, api.CK_FALSE),
            (api.CKA_VERIFY, api.CK_FALSE),
            (api.CKA_VALUE_LEN, 256//8),
            (api.CKA_LABEL, self.keyLABEL),
            (api.CKA_ID, self.keyID),
        ]

        self.AESKey = self.session.generateKey(AESKeyTemplate, api.MechanismAESGENERATEKEY)

    def destroyKey(self):
        self.session.destroyObject(self.AESKey)

    def encryptInit(self, key, mech):
        rc = self.pkcs11.funcs.C_EncryptInit(self.session.hsession, api.byref(mech), key)
        if rc != api.CKR_OK:
            raise HSMError(rc, "C_EncryptInit")

    def encryptBlock(self, data):
        if len(data) == 0:
            edatalen = api.c_ulong(0)
            rc = self.pkcs11.funcs.C_EncryptFinal(self.session.hsession, None, api.byref(edatalen))
            if rc != api.CKR_OK:
                raise HSMError(rc, "C_EncryptFinal")
            edata = api.buffer(edatalen.value)
            rc = self.pkcs11.funcs.C_EncryptFinal(self.session.hsession, api.byref(edata), api.byref(edatalen))
            if rc != api.CKR_OK:
                raise HSMError(rc, "C_EncryptFinal")
        else:
            bdata = api.buffer(data)
            edatalen = api.c_ulong(0)
            rc = self.pkcs11.funcs.C_EncryptUpdate(self.session.hsession, api.byref(bdata), len(bdata), None, api.byref(edatalen))
            if rc != api.CKR_OK:
                raise HSMError(rc, "C_Encrypt")
            edata = api.buffer(edatalen.value)
            rc = self.pkcs11.funcs.C_EncryptUpdate(self.session.hsession, api.byref(bdata), len(bdata), api.byref(edata), api.byref(edatalen))
            if rc != api.CKR_OK:
                raise HSMError(rc, "C_Encrypt")
        return bytes(edata)

    def decryptInit(self, key, mech):
        rc = self.pkcs11.funcs.C_DecryptInit(self.session.hsession, api.byref(mech), key)
        if rc != api.CKR_OK:
            raise HSMError(rc, "C_DecryptInit")

    def decryptBlock(self, data):
        if not data:
            ddatalen = api.c_ulong(0)
            rc = self.pkcs11.funcs.C_DecryptFinal(self.session.hsession, None, api.byref(ddatalen))
            if rc != api.CKR_OK:
                raise HSMError(rc, "C_DecryptFinal")
            ddata = api.buffer(ddatalen.value)
            rc = self.pkcs11.funcs.C_DecryptFinal(self.session.hsession, api.byref(ddata), api.byref(ddatalen))
            if rc != api.CKR_OK:
                raise HSMError(rc, "C_DecryptFinal")
        else:
            bdata = api.buffer(data)
            ddatalen = api.c_ulong(0)
            rc = self.pkcs11.funcs.C_DecryptUpdate(self.session.hsession, api.byref(bdata), len(bdata), None, api.byref(ddatalen))
            if rc != api.CKR_OK:
                raise HSMError(rc, "C_Decrypt")
            ddata = api.buffer(ddatalen.value)
            rc = self.pkcs11.funcs.C_DecryptUpdate(self.session.hsession, api.byref(bdata), len(bdata), api.byref(ddata), api.byref(ddatalen))
            if rc != api.CKR_OK:
                raise HSMError(rc, "C_Decrypt")
        return bytes(ddata[: ddatalen.value])

    def test_symetric_stream(self):
        self.setupKey()
        try:
            key = self.session.findObjects([
                (api.CKA_CLASS, api.CKO_SECRET_KEY),
                (api.CKA_ID, self.keyID)
            ])[0]
            gcmIV = bytes([
                0xCA, 0xFE, 0xBA, 0xBE, 0xFA, 0xCE,
                0xDB, 0xAD, 0xDE, 0xCA, 0xF8, 0x88
            ])
            gcmAAD = bytes([
                0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xBE, 0xEF,
                0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xBE, 0xEF,
                0xAB, 0xAD, 0xDA, 0xD2
            ])
            mechanism = api.AES_GCM_Mechanism(gcmIV, gcmAAD, 16*8)
            with open(__file__, 'rb') as fp:
                udata = fp.read()

            fpu = io.BytesIO(udata)
            fpe = io.BytesIO()
            self.encryptInit(key, mechanism)
            b = True
            while b:
                b = fpu.read(131)
                edata = self.encryptBlock(b)
                fpe.write(edata)
            fpe.seek(0, 0)

            fpd = io.BytesIO()
            self.decryptInit(key, mechanism)
            b = True
            while b:
                b = fpe.read(131)
                edata = self.decryptBlock(b)
                fpd.write(edata)
            ddata = fpd.getvalue()

            self.assertEqual(udata, ddata)

        finally:
            self.destroyKey()



if __name__ == '__main__':
    import unittest
    unittest.main()
