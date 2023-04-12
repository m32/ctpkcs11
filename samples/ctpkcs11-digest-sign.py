#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import hashlib
import ctypes
from pkcsconfig import Config
from ctpkcs11 import HSM, pkcsapi

class Signer(HSM):
    session = None

    def getSlot(self, label):
        slots = self.getSlotList(tokenPresent=True)
        for slot in slots:
            info = self.getTokenInfo(slot)
            if info.label == label:
                return slot
        return None

    def login(self, label, pin):
        slot = self.getSlot(label)
        if slot is None:
            raise IOError(2)
        self.session = self.openSession(slot)
        self.session.login(pin)

    def logout(self):
        if self.session is not None:
            self.session.logout()
            self.session.closeSession()
            self.session = None

    def certificate(self, label, pin, keyid):
        self.login(label, pin)
        try:
            pk11objects = self.session.findObjects(
                [(pkcsapi.CKA_CLASS, pkcsapi.CKO_CERTIFICATE)]
            )
            all_attributes = [
                # pkcsapi.CKA_SUBJECT,
                pkcsapi.CKA_VALUE,
                # pkcsapi.CKA_ISSUER,
                # pkcsapi.CKA_CERTIFICATE_CATEGORY,
                # pkcsapi.CKA_END_DATE,
                pkcsapi.CKA_ID,
            ]

            for pk11object in pk11objects:
                try:
                    attributes = self.session.getAttributeValue(
                        pk11object, all_attributes
                    )
                except AssertionError:
                    continue

                attrDict = dict(list(zip(all_attributes, attributes)))
                cert = bytes(attrDict[pkcsapi.CKA_VALUE])
                if keyid == bytes(attrDict[pkcsapi.CKA_ID]):
                    return keyid, cert
        finally:
            self.logout()
        return None, None

    def sign(self, label, pin, keyid, data, smech):
        self.login(label, pin)
        try:
            privKey = self.session.findObjects([
                (pkcsapi.CKA_CLASS, pkcsapi.CKO_PRIVATE_KEY),
                (pkcsapi.CKA_ID, keyid)
            ])[0]
            mech = pkcsapi.Mechanism(getattr(pkcsapi, smech))
            sig = self.session.sign(privKey, data, mech)
            return bytes(sig)
        finally:
            self.logout()

    def verify(self, label, pin, keyid, data, signature, smech):
        self.login(label, pin)
        try:
            pubKey = self.session.findObjects([
                (pkcsapi.CKA_CLASS, pkcsapi.CKO_PUBLIC_KEY),
                (pkcsapi.CKA_ID, keyid)
            ])[0]
            mech = pkcsapi.ck_mechanism(getattr(pkcsapi, smech))
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
    cls.open()
    try:
        data = b"Hello, world!\n"
        if 0:
            from asn1crypto import pem, x509
            rkeyid, derbytes = cls.certificate(cfg.label, cfg.pin, cfg.keyid)
            print('keyid=', cfg.keyid, 'rkeyid=', rkeyid)

            cert = pem.armor("CERTIFICATE", derbytes).decode('utf8')
            print(cert)

            _, _, cert_bytes = pem.unarmor(cert.encode())
            cert = x509.Certificate.load(cert_bytes)
            print('issuer :', cert.issuer.native)
            print('subject:', cert.subject.native)

        for smech in (
            #"md5",
            "sha1",
            "sha256",
            "sha384",
            "sha512"
        ):
            print("*" * 20, smech)
            sig1 = cls.sign(cfg.label, cfg.pin, cfg.keyid, data, "CKM_%s_RSA_PKCS" % smech.upper())
            ssig1 = sig1.hex()
            print("sig1:", ssig1[:10], "...", ssig1[-10:])

            ok = cls.verify(cfg.label, cfg.pin, cfg.keyid, data, sig1, "CKM_%s_RSA_PKCS" % smech.upper())
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
            sig3 = cls.sign(cfg.label, cfg.pin, cfg.keyid, data3, "CKM_RSA_PKCS")
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
            sig4 = cls.sign(cfg.label, cfg.pin, cfg.keyid, data4, "CKM_RSA_PKCS")
            ssig4 = sig4.hex()
            print("sig4:", ssig4[:10], "...", ssig4[-10:])
            print("OK?", sig1 == sig3 and sig1 == sig4)
            if 0:
                print('OK1/3=', sig1 == sig3)
                print('OK1/4=', sig1 == sig4)
                print(ssig1)
                print(ssig3)
                print(ssig4)
    finally:
        cls.close()

if __name__ == "__main__":
    main()
