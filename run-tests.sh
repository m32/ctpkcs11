#!/bin/sh
set +x
#
# https://about.codecov.io/blog/python-code-coverage-using-github-actions-and-codecov/
#
#vpy3-pytest --cov=./endesive --cov-report=xml $*
top=$(pwd)
mkdir -p $top/tests/softhsm2
SOFTHSM2_CONF=$top/tests/softhsm2.conf
cat >$SOFTHSM2_CONF <<-EOF
log.level = DEBUG
directories.tokendir = tests/softhsm2/
objectstore.backend = file
slots.removable = false
EOF

export PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
export PKCS11_TOKEN_LABEL=token
export PKCS11_TOKEN_PIN=1234
export PKCS11_TOKEN_SO_PIN=12345678
export OPENSSL_PATH=/usr/bin

SOFTHSM2_CONF=$(pwd)/tests/softhsm2.conf
rm -rf tests/softhsm2
mkdir tests/softhsm2
softhsm2-util --init-token --label "A token" --pin 1234 --so-pin 123456 --slot 0

vpython3 -m coverage run \
-m unittest discover tests
vpy3-coverage3 report -m
