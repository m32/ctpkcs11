#!/bin/bash
#
# https://developers.yubico.com/yubico-piv-tool/YKCS11/Supported_applications/pkcs11tool.html
# https://developers.yubico.com/yubico-piv-tool/YKCS11/Functions_and_values.html
#
top=$(pwd)
export PKCS11_MODULE=/usr/lib/x86_64-linux-gnu/libykcs11.so
export PKCS11_TOKEN_LABEL=token
export PKCS11_TOKEN_PIN=1234
export PKCS11_TOKEN_SO_PIN=12345678
export OPENSSL_PATH=/usr/bin

pkcs11-tool --module $PKCS11_MODULE --show-info
#pkcs11-tool --module $PKCS11_MODULE --login  --test

# slot 9a
# pkcs11-tool --module $PKCS11_MODULE --login --login-type so --keypairgen --id 1 --key-type EC:secp384r1
# slot 9e
# pkcs11-tool --module $PKCS11_MODULE --login --login-type so --keypairgen --id 4 --key-type EC:prime256v1
# slot 9c
# pkcs11-tool --module $PKCS11_MODULE --login --login-type so --keypairgen --id 2 --key-type rsa:2048
#
# pkcs11-tool --module $PKCS11_MODULE --sign --id 4 -i data.txt -o data.sig
# pkcs11-tool --module $PKCS11_MODULE --sign -m RSA-SHA256 --id 2 -i data.txt -o data.sig
# pkcs11-tool --module $PKCS11_MODULE --sign --id 1 -m ECDSA-SHA1 --signature-format openssl -i data.txt -o data.sig
# pkcs11-tool --module $PKCS11_MODULE --login --login-type so --test-ec --id 2 --key-type EC:secp256r1
