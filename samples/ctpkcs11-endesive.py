#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import sys
import datetime
from endesive import pdf
from pkcsconfig import Config
from ctpkcs11 import pkcsapi, HSMError
import endesivehsm as hsm

class Signer(hsm.HSM):
    cfg = None

    def setConfigData(self, cfg):
        self.cfg = cfg

    def certificate(self):
        self.login(self.cfg.label, self.cfg.pin)
        keyid = self.cfg.keyid
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
        self.login(self.cfg.label, self.cfg.pin)
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
    clshsm = Signer(cfg.dllpath)
    clshsm.open()
    try:
        clshsm.setConfigData(cfg)
        fname = cfg.options.pdffile
        datau = open(fname, 'rb').read()
        datas = pdf.cms.sign(datau, dct,
            None, None,
            [],
            'sha256',
            clshsm,
#            tspurl,
        )
        fname = fname.replace('.pdf', '-signed-{}.pdf'.format(cfg.options.config))
        with open(fname, 'wb') as fp:
            fp.write(datau)
            fp.write(datas)
    finally:
        clshsm.close()

main()
