#!/usr/bin/env vpython3
from pkcsconfig import Config
from ctpkcs11 import pkcsapi, HSM

def main():
    cfg = Config()
    cls = HSM(cfg.dllpath)
    cls.open()
    try:
        slots = cls.getSlotList(False)
        for slot in slots:
            mechs = cls.getMechanismList(slot)
            for mech in mechs:
                print('Mechanisms(slot={})={} {}'.format(slot, mech, pkcsapi.CKM[mech]))
        slots = cls.getSlotList(True)
        for slot in slots:
            mechs = cls.getMechanismList(slot)
            for mech in mechs:
                print('Mechanisms(slot={})={} {}'.format(slot, mech, pkcsapi.CKM[mech]))
    finally:
        cls.close()

main()
