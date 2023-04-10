#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import padding

def main():
    p12name = sys.argv[1]
    p12pass = sys.argv[2]
    output = sys.argv[3]
    p12key, p12cert, p12other = pkcs12.load_key_and_certificates(open(p12name, 'rb').read(), p12pass.encode())
    print('subject:', p12cert.subject)
    print('issuer :', p12cert.issuer)
    for cert in p12other:
        print('*'*10)
        print('subject:', cert.subject)
        print('issuer :', cert.issuer)
    signature = p12key.sign(
        b"message",
        padding.PKCS1v15(),
        hashes.SHA1()
    )
    with open(output+'.crt.der', 'wb') as f:
        f.write(p12cert.public_bytes(serialization.Encoding.DER))
    with open(output+'.pub.der', 'wb') as f:
        f.write(p12key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    with open(output+'.key.der', 'wb') as f:
        f.write(p12key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
#            encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8')),
        ))

main()
