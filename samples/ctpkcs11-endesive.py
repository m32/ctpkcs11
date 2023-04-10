#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import sys
import datetime
from endesive import pdf
from pkcsconfig import Config
from ctpkcs11 import pkcsapi, HSMError
import endesivehsm as hsm

class Signer(hsm.HSM):
    def certificate(self):
        self.login("endesieve", "secret1")
        keyid = bytes((0x66,0x66,0x90))
        try:
            pk11objects = self.session.findObjects([
                (pkcsapi.CKA_CLASS, pkcsapi.CKO_CERTIFICATE)
            ])
            all_attributes = [
                pkcsapi.CKA_VALUE,
                pkcsapi.CKA_ID,
            ]

            for pk11object in pk11objects:
                try:
                    attributes = self.session.getAttributeValue(pk11object, all_attributes)
                except HSMError as e:
                    continue

                attrDict = dict(list(zip(all_attributes, attributes)))
                cert = bytes(attrDict[pkcsapi.CKA_VALUE])
                if keyid == bytes(attrDict[pkcsapi.CKA_ID]):
                    return keyid, cert
        finally:
            self.logout()
        return None, None

    def sign(self, keyid, data, mech):
        self.login("endesieve", "secret1")
        try:
            privKey = self.session.findObjects([
                (pkcsapi.CKA_CLASS, pkcsapi.CKO_PRIVATE_KEY),
                (pkcsapi.CKA_ID, keyid)
            ])[0]
            mech = pkcsapi.ck_mechanism(getattr(pkcsapi, 'CKM_%s_RSA_PKCS' % mech.upper()))
            sig = self.session.sign(privKey, data, mech)
            return bytes(sig)
        finally:
            self.logout()

def main():
    tspurl = "http://time.certum.pl"
    tspurl = "http://public-qlts.certum.pl/qts-17"
    date = datetime.datetime.utcnow() - datetime.timedelta(hours=12)
    date = date.strftime('D:%Y%m%d%H%M%S+00\'00\'')
    dct = {
        'sigflags': 3,
        'contact': 'mak@trisoft.com.pl',
        'location': 'Szczecin',
        'signingdate': date.encode(),
        'reason': 'Dokument podpisany cyfrowo',
    }
    cfg = Config()
    cfg.SoftHSMInit()
    clshsm = Signer(cfg.dllpath)
    fname = 'pdf.pdf'
    if len (sys.argv) > 1:
        fname = sys.argv[1]
    datau = open(fname, 'rb').read()
    datas = pdf.cms.sign(datau, dct,
        None, None,
        [],
        'sha256',
        clshsm,
#        tspurl,
    )
    fname = fname.replace('.pdf', '-signed-ctpkcs11.pdf')
    with open(fname, 'wb') as fp:
        fp.write(datau)
        fp.write(datas)


main()
