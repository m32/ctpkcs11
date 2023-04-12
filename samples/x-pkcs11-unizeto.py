#!/usr/bin/env vpython3
import sys
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

def main():
    fqname = sys.argv[1]
    password = sys.argv[2]
    with open(fqname, 'rb') as fp:
        p12pk, p12pc, p12oc = pkcs12.load_key_and_certificates(fp.read(), password.encode(), backends.default_backend())
    with open('cert.crt.der', 'wb') as fp:
        fp.write(p12pc.public_bytes(serialization.Encoding.DER))
    with open('cert.pub.der', 'wb') as fp:
        fp.write(
            p12pk.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    with open('cert.pri.der', 'wb') as fp:
        fp.write(
            p12pk.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

main()
