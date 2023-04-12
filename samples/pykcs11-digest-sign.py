#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import sys
import hashlib
import PyKCS11
from pkcsconfig import Config
from endesive.hsm import HSM

class Signer(HSM):
    session = None

    def certificate(self, label, pin):
        self.login(label, pin)
        keyid = bytes((0x66, 0x66, 0x90))
        try:
            pk11objects = self.session.findObjects(
                [(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)]
            )
            all_attributes = [
                # PK11.CKA_SUBJECT,
                PyKCS11.CKA_VALUE,
                # PK11.CKA_ISSUER,
                # PK11.CKA_CERTIFICATE_CATEGORY,
                # PK11.CKA_END_DATE,
                PyKCS11.CKA_ID,
            ]

            for pk11object in pk11objects:
                try:
                    attributes = self.session.getAttributeValue(
                        pk11object, all_attributes
                    )
                except AssertionError:
                    continue

                attrDict = dict(list(zip(all_attributes, attributes)))
                cert = bytes(attrDict[PyKCS11.CKA_VALUE])
                if keyid == bytes(attrDict[PyKCS11.CKA_ID]):
                    return keyid, cert
        finally:
            self.logout()
        return None, None

    def sign(self, label, pin, keyid, data, mech):
        self.login(label, pin)
        try:
            privKey = self.session.findObjects(
                [(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY), (PyKCS11.CKA_ID, keyid)]
            )[0]
            #print('privKey=', privKey)
            #mech = getattr(pkcs, 'CKM_%s_RSA_PKCS' % mech.upper())
            mech = PyKCS11.Mechanism(mech, None)
            sig = self.session.sign(privKey, data, mech)
            return bytes(sig)
        finally:
            self.logout()

    def verify(self, label, pin, keyid, data, signature, mech):
        self.login(label, pin)
        try:
            pubKey = self.session.findObjects([
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
                (PyKCS11.CKA_ID, keyid)
            ])[0]
            mech = PyKCS11.Mechanism(mech, None)
            ok = self.session.verify(pubKey, data, signature, mech)
            return ok
        finally:
            self.logout()

DigestInfo = {
    "MD5":   (0x30,0x20,0x30,0x0C,0x06,0x08,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x02,0x05,0x05,0x00,0x04,0x10,),
    "SHA1":  (0x30,0x21,0x30,0x09,0x06,0x05,0x2B,0x0E,0x03,0x02,0x1A,0x05,0x00,0x04,0x14,),
    "SHA256":(0x30,0x31,0x30,0x0D,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20,),
    "SHA384":(0x30,0x41,0x30,0x0D,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02,0x05,0x00,0x04,0x30,),
    "SHA512":(0x30,0x51,0x30,0x0D,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,0x05,0x00,0x04,0x40,),
}


def main():
    # https://stackoverflow.com/questions/50273289/pkcs11interop-hash-with-sha256-and-sign-with-rsa-in-two-steps
    # Mechanims CKM_SHA256_RSA_PKCS does following things:
    #
    # 1. Computes SHA256 hash of the data just like CKM_SHA256 does
    # 2. Constructs DER encoded DigestInfo structure defined in RFC 8017
    # 3. Signs DigestInfo structure with private key just like CKM_RSA_PKCS does
    from asn1crypto import core, algos

    cfg = Config()
    cls = Signer(cfg.dllpath)
    if 1:
        data = b"Hello, world!\n"
        for smech in ("md5", "sha1", "sha256", "sha384", "sha512"):
            print("*" * 20, smech)
            mech = getattr(PyKCS11, "CKM_%s_RSA_PKCS" % smech.upper())
            sig1 = cls.sign(cfg.label, cfg.pin, cfg.keyid, data, mech)
            ssig1 = sig1.hex()
            print("sig1:", ssig1[:10], "...", ssig1[-10:])

            ok = cls.verify(cfg.label, cfg.pin, cfg.keyid, data, sig1, mech)
            print('verify=', ok)

            data_digest = getattr(hashlib, smech)(data).digest()

            # mech = getattr(pkcs, "CKM_RSA_PKCS")
            # sig2 = cls.sign(keyid, data_digest, mech)
            # print("sig2:", sig2.hex())

            b = bytes(DigestInfo[smech.upper()])
            data3 = b + data_digest
            if 0:
                bb = core.load(data3)
                bb.debug()
            sig3 = cls.sign(cfg.label, cfg.pin, cfg.keyid, data3, getattr(PyKCS11, "CKM_RSA_PKCS"))
            ssig3 = sig3.hex()
            print("sig3:", ssig3[:10], "...", ssig3[-10:])

            data4 = algos.DigestInfo(
                {
                    "digest_algorithm": algos.DigestAlgorithm(
                        {
                            "algorithm": smech,
                            "parameters": algos.Null()
                        }
                    ),
                    "digest": data_digest,
                }
            ).dump()
            if 0:
                bb = core.load(data4)
                bb.debug()
            sig4 = cls.sign(cfg.label, cfg.pin, cfg.keyid, data4, getattr(PyKCS11, "CKM_RSA_PKCS"))
            ssig4 = sig4.hex()
            print("sig4:", ssig4[:10], "...", ssig4[-10:])
            print("OK?", sig1 == sig3 and sig1 == sig4)
            if 0:
                print('OK1/3=', sig1 == sig3)
                print('OK1/4=', sig1 == sig4)
                print(sig1)
                print(sig3)
                print(sig4)

if __name__ == "__main__":
    main()
