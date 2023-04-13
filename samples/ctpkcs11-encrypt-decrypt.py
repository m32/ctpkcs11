#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import binascii
from pkcsconfig import Config
from ctpkcs11 import HSM, pkcsapi
from endesivehsm import Signer

def main():
    cfg = Config()
    cls = Signer(cfg.dllpath)
    cls.open()
    try:
        udata = "48656c6c6f20776f726c640d0a"
        udata = binascii.unhexlify(udata)
        mech = pkcsapi.Mechanism(pkcsapi.CKM_RSA_PKCS)
        edata = cls.encrypt(cfg.label, cfg.pin, cfg.keyid, udata, mech)
        ddata = cls.decrypt(cfg.label, cfg.pin, cfg.keyid, edata, mech)
        print('OK?', udata == ddata)
    finally:
        cls.close()

if __name__ == "__main__":
    main()
