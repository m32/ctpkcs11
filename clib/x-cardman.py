#!/usr/bin/env vpython3
import _ctypes
from ctypes import *

lcrypto = CDLL("/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1", RTLD_GLOBAL)
lssl = CDLL("/usr/lib/x86_64-linux-gnu/libssl.so.1.1", RTLD_GLOBAL)
lcertum = CDLL("/devel/lib/pkcs11libs/sc30pkcs11-3.0.5.60-MS.so")

rdata = '12345678'.encode('ascii')
result = bytes([9]*256)

sc35GetTokenInfo        = 0x00000000000ae9d0
sc35getUninitializedPuk = 0x00000000000ade50
offset = sc35getUninitializedPuk - sc35GetTokenInfo

addr = _ctypes.dlsym(lcertum._handle, "sc35GetTokenInfo")
print('dlsym', hex(addr))
proc = CFUNCTYPE(None, c_void_p, c_void_p)(addr+offset)

if 1:
    random_data = bytes([1,2,3,4,5,6,7,8])
    puk = bytes([0]*32)
    proc(random_data, puk)
    print([b for b in puk])

for name in (
    'sc35Login', 'sc35checkPinPolicy',
    'ports'
):
    try:
        addr = _ctypes.dlsym(lcertum._handle, name)
    except OSError as why:
        addr = 0
    print(name, '=', hex(addr))
