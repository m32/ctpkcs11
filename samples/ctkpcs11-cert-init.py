#!/usr/bin/env vpython3
# coding: utf-8

import os
from pkcsconfig import Config
from ctpkcs11 import pkcsapi
import endesivehsm as hsm

'''
Create two certificates:
1. self signed hsm CA certificate with serial equal to HSM keyID=0x01
2. hsm USER 1 certificate with serial equal to HSM keyID=0x666690
'''
class HSM(hsm.HSM):
    def main(self):
        cakeyID = bytes((0x01,))
        rec = self.session.findObjects([
            (pkcsapi.CKA_CLASS, pkcsapi.CKO_PRIVATE_KEY),
            (pkcsapi.CKA_ID, cakeyID)
        ])
        if len(rec) == 0:
            print('create CA')
            label = 'hsm CA'
            self.gen_privkey(label, cakeyID)
            self.ca_gen(label, cakeyID, 'hsm CA')

        keyID = bytes((0x66, 0x66, 0x90))
        rec = self.session.findObjects([
            (pkcsapi.CKA_CLASS, pkcsapi.CKO_PRIVATE_KEY),
            (pkcsapi.CKA_ID, keyID)
        ])
        if len(rec) == 0:
            print('create USER')
            label = 'hsm USER 1'
            self.gen_privkey(label, keyID)
            self.ca_sign(keyID, label, 0x666690, "hsm USER 1", 365, cakeyID)

        self.cert_export('cert-hsm-ca', cakeyID)
        self.cert_export('cert-hsm-user1', keyID)

def main():
    cfg = Config()
    assert cfg.options.config == 'softhsm2'

    cls = HSM(cfg.dllpath)
    cls.create(cfg.label, cfg.pin, cfg.sopin)
    cls.login(cfg.label, cfg.pin)
    try:
        cls.main()
    finally:
        cls.logout()
main()
