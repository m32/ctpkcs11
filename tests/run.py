#!/usr/bin/env vpython3
import os
import sys

sys.path.insert(1, '..')

def setenv(name, value):
    os.environ[name] = value

setenv('SOFTHSM2_CONF', os.path.join(os.getcwd(), 'softhsm2.conf'))
setenv('PKCS11_MODULE', '/usr/lib/softhsm/libsofthsm2.so')
setenv('PKCS11_TOKEN_LABEL', 'token')
setenv('PKCS11_TOKEN_PIN', '1234')
setenv('PKCS11_TOKEN_SO_PIN', '12345678')
setenv('OPENSSL_PATH', '/usr/bin')
