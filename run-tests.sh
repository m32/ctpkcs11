#!/bin/sh
top=$(pwd)
mkdir -p $top/tests/softhsm2
export SOFTHSM2_CONF=$top/tests/softhsm2.conf
cat >$SOFTHSM2_CONF <<-EOF
log.level = DEBUG
directories.tokendir = $top/tests/softhsm2/
objectstore.backend = file
slots.removable = false
EOF

export PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
export PKCS11_TOKEN_LABEL=token
export PKCS11_TOKEN_PIN=1234
export PKCS11_TOKEN_SO_PIN=12345678
export OPENSSL_PATH=/usr/bin

rm -rf tests/softhsm2
mkdir tests/softhsm2
softhsm2-util --init-token --label "A token" --pin 1234 --so-pin 123456 --slot 0

vpython3 -m coverage run \
-m unittest discover tests
vpy3-coverage3 report -m
