#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import io
import binascii
import ctypes as ct
from pkcsconfig import Config
from ctpkcs11 import HSM, pkcsapi, HSMError
from endesivehsm import Signer

class MySigner(Signer):
    keyID = (0x01,)
    keyLABEL = "TestAESKey"
    def createAES(self):
        AESKeyTemplate = [
            (pkcsapi.CKA_CLASS, pkcsapi.CKO_SECRET_KEY),
            (pkcsapi.CKA_KEY_TYPE, pkcsapi.CKK_AES),
            (pkcsapi.CKA_TOKEN, pkcsapi.CK_TRUE),
            (pkcsapi.CKA_PRIVATE, pkcsapi.CK_FALSE),
            (pkcsapi.CKA_ENCRYPT, pkcsapi.CK_TRUE),
            (pkcsapi.CKA_DECRYPT, pkcsapi.CK_TRUE),
            (pkcsapi.CKA_SIGN, pkcsapi.CK_FALSE),
            (pkcsapi.CKA_VERIFY, pkcsapi.CK_FALSE),
            (pkcsapi.CKA_VALUE_LEN, 256//8),
            (pkcsapi.CKA_LABEL, self.keyLABEL),
            (pkcsapi.CKA_ID, self.keyID),
        ]

        self.AESKey = self.session.generateKey(AESKeyTemplate, pkcsapi.MechanismAESGENERATEKEY)

    def destroyAES(self):
        self.session.destroyObject(self.AESKey)

class StreamSigner:
    def __init__(self, signer, keyid, mech):
        self.signer = signer
        self.keyid = keyid
        self.mech = mech
        self.session = self.signer.session
        self.hsm = self.signer.session.hsm
        self.key = self.signer.session.findObjects([
            (pkcsapi.CKA_CLASS, pkcsapi.CKO_SECRET_KEY),
            (pkcsapi.CKA_ID, self.keyid)
        ])[0]

    def close(self):
        self.session = None
        self.hsm = None

class StreamEncrypt(StreamSigner):
    def __init__(self, signer, keyid, mech):
        super().__init__(signer, keyid, mech)
        rc = self.hsm.funcs.C_EncryptInit(self.session.hsession, ct.byref(self.mech), self.key)
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_EncryptInit")

    def encrypt(self, data):
        if len(data) == 0:
            edatalen = ct.c_ulong(0)
            rc = self.hsm.funcs.C_EncryptFinal(self.session.hsession, None, ct.byref(edatalen))
            if rc != pkcsapi.CKR_OK:
                raise HSMError(rc, "C_EncryptFinal")
            edata = pkcsapi.buffer(edatalen.value)
            rc = self.hsm.funcs.C_EncryptFinal(self.session.hsession, ct.byref(edata), ct.byref(edatalen))
            if rc != pkcsapi.CKR_OK:
                raise HSMError(rc, "C_EncryptFinal")
        else:
            bdata = pkcsapi.buffer(data)
            edatalen = ct.c_ulong(0)
            rc = self.signer.session.hsm.funcs.C_EncryptUpdate(self.session.hsession, ct.byref(bdata), len(bdata), None, ct.byref(edatalen))
            if rc != pkcsapi.CKR_OK:
                raise HSMError(rc, "C_Encrypt")
            edata = pkcsapi.buffer(edatalen.value)
            rc = self.hsm.funcs.C_EncryptUpdate(self.session.hsession, ct.byref(bdata), len(bdata), ct.byref(edata), ct.byref(edatalen))
            if rc != pkcsapi.CKR_OK:
                raise HSMError(rc, "C_Encrypt")
        return bytes(edata)


class StreamDecrypt(StreamSigner):
    def __init__(self, signer, keyid, mech):
        super().__init__(signer, keyid, mech)
        rc = self.hsm.funcs.C_DecryptInit(self.session.hsession, ct.byref(mech), self.key)
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_DecryptInit")

    def decrypt(self, data):
        if not data:
            ddatalen = ct.c_ulong(0)
            rc = self.hsm.funcs.C_DecryptFinal(self.session.hsession, None, ct.byref(ddatalen))
            if rc != pkcsapi.CKR_OK:
                raise HSMError(rc, "C_DecryptFinal")
            ddata = pkcsapi.buffer(ddatalen.value)
            rc = self.hsm.funcs.C_DecryptFinal(self.session.hsession, ct.byref(ddata), ct.byref(ddatalen))
            if rc != pkcsapi.CKR_OK:
                raise HSMError(rc, "C_DecryptFinal")
        else:
            bdata = pkcsapi.buffer(data)
            ddatalen = ct.c_ulong(0)
            rc = self.hsm.funcs.C_DecryptUpdate(self.session.hsession, ct.byref(bdata), len(bdata), None, ct.byref(ddatalen))
            if rc != pkcsapi.CKR_OK:
                raise HSMError(rc, "C_Decrypt")
            ddata = pkcsapi.buffer(ddatalen.value)
            rc = self.hsm.funcs.C_DecryptUpdate(self.session.hsession, ct.byref(bdata), len(bdata), ct.byref(ddata), ct.byref(ddatalen))
            if rc != pkcsapi.CKR_OK:
                raise HSMError(rc, "C_Decrypt")
        return bytes(ddata[: ddatalen.value])

def main():
    cfg = Config()
    cls = MySigner(cfg.dllpath)
    cls.open()
    try:
        gcmIV = bytes([
            0xCA, 0xFE, 0xBA, 0xBE, 0xFA, 0xCE,
            0xDB, 0xAD, 0xDE, 0xCA, 0xF8, 0x88
        ])
        gcmAAD = bytes([
            0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xBE, 0xEF,
            0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xBE, 0xEF,
            0xAB, 0xAD, 0xDA, 0xD2
        ])
        mechanism = pkcsapi.AES_GCM_Mechanism(gcmIV, gcmAAD, 16*8)
        cls.login(cfg.label, cfg.pin)
        try:
            cls.createAES()
            try:
                udata = open(__file__, 'rb').read()
                fpu = io.BytesIO(udata)
                fpe = io.BytesIO()
                enc = StreamEncrypt(cls, cls.keyID, mechanism)
                try:
                    b = True
                    while b:
                        b = fpu.read(131)
                        edata = enc.encrypt(b)
                        fpe.write(edata)
                finally:
                    enc.close()
                fpe.seek(0, 0)
                fpd = io.BytesIO()
                dec = StreamDecrypt(cls, cls.keyID, mechanism)
                try:
                    b = True
                    while b:
                        b = fpe.read(131)
                        edata = dec.decrypt(b)
                        fpd.write(edata)
                finally:
                    dec.close()
                ddata = fpd.getvalue()
                print('OK?', udata == ddata)
            finally:
                cls.destroyAES()
        finally:
            cls.logout()
    finally:
        cls.close()

if __name__ == "__main__":
    main()
