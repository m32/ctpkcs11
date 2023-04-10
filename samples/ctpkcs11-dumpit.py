#!/usr/bin/env vpython3
from pkcsconfig import Config
from ctpkcs11 import HSM

def main():
    cfg = Config()
    cfg.SoftHSMInit()
    cfg.endesive()

    print(cfg.dllpath, cfg.label, cfg.pin)

    cls = HSM(cfg.dllpath)
    cls.open()
    try:
        cls.displayInfo()
        cls.displaySlots(0, cfg.pin)
        cls.displaySlots(1, cfg.pin)
    finally:
        cls.close()

main()
