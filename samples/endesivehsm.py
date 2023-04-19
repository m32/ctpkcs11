#!/usr/bin/env vpython3
# coding: utf-8

import os
import sys
import binascii
import datetime
import base64
import hashlib

import cryptography
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

from asn1crypto import x509 as asn1x509
from asn1crypto import keys as asn1keys
from asn1crypto import pem as asn1pem
from asn1crypto import util as asn1util

import ctpkcs11

class BaseHSM:
    def certificate(self):
        raise NotImplementedError()

    def sign(self, keyid, data, mech):
        raise NotImplementedError()


class HSM(BaseHSM):
    def __init__(self, dllpath):
        self.pkcs11 = ctpkcs11.HSM(dllpath)
        self.session = None

    def open(self):
        self.pkcs11.open()

    def close(self):
        self.pkcs11.close()

    def getSlot(self, label):
        slots = self.pkcs11.getSlotList(tokenPresent=True)
        for slot in slots:
            info = self.pkcs11.getTokenInfo(slot)
            try:
                if info.label.split("\0")[0].strip() == label:
                    return slot
            except AttributeError:
                continue
        return None

    def create(self, label, pin, sopin):
        slot = self.getSlot(label)
        if slot is not None:
            return
        slot = self.pkcs11.getSlotList(tokenPresent=True)[0]
        self.pkcs11.initToken(slot, sopin, label)
        session = self.pkcs11.openSession(
            slot, ctpkcs11.api.CKF_SERIAL_SESSION | ctpkcs11.api.CKF_RW_SESSION
        )
        session.login(sopin, user_type=ctpkcs11.api.CKU_SO)
        session.initPin(pin)
        session.logout()
        session.close()

    def login(self, label, pin):
        slot = self.getSlot(label)
        if slot is None:
            return
        self.session = self.pkcs11.openSession(
            slot, ctpkcs11.api.CKF_SERIAL_SESSION | ctpkcs11.api.CKF_RW_SESSION
        )
        self.session.login(pin)

    def logout(self):
        if self.session is not None:
            self.session.logout()
            self.session.close()
            self.session = None

    def gen_privkey(self, label, key_id, key_length=2048):
        # label - just a label for identifying objects
        # key_id has to be the same for both objects, it will also be necessary
        #     when importing the certificate, to ensure it is linked with these keys.
        # key_length - key-length in bits

        public_template = [
            (ctpkcs11.api.CKA_CLASS, ctpkcs11.api.CKO_PUBLIC_KEY),
            (ctpkcs11.api.CKA_TOKEN, ctpkcs11.api.CK_TRUE),
            (ctpkcs11.api.CKA_PRIVATE, ctpkcs11.api.CK_FALSE),
            (ctpkcs11.api.CKA_MODULUS_BITS, key_length),
            #(ctpkcs11.api.CKA_PUBLIC_EXPONENT, (0x01, 0x00, 0x01)),
            (ctpkcs11.api.CKA_ENCRYPT, ctpkcs11.api.CK_TRUE),
            (ctpkcs11.api.CKA_VERIFY, ctpkcs11.api.CK_TRUE),
            (ctpkcs11.api.CKA_VERIFY_RECOVER, ctpkcs11.api.CK_TRUE),
            (ctpkcs11.api.CKA_WRAP, ctpkcs11.api.CK_TRUE),
            (ctpkcs11.api.CKA_LABEL, label),
            (ctpkcs11.api.CKA_ID, key_id)
            #(ctpkcs11.api.CKA_KEY_TYPE, ctpkcs11.api.CKK_RSA),
            #(ctpkcs11.api.CKA_SENSITIVE, ctpkcs11.api.CK_FALSE),
        ]

        private_template = [
            (ctpkcs11.api.CKA_CLASS, ctpkcs11.api.CKO_PRIVATE_KEY),
            (ctpkcs11.api.CKA_TOKEN, ctpkcs11.api.CK_TRUE),
            (ctpkcs11.api.CKA_PRIVATE, ctpkcs11.api.CK_TRUE),
            (ctpkcs11.api.CKA_DECRYPT, ctpkcs11.api.CK_TRUE),
            (ctpkcs11.api.CKA_SIGN, ctpkcs11.api.CK_TRUE),
            (ctpkcs11.api.CKA_SIGN_RECOVER, ctpkcs11.api.CK_TRUE),
            (ctpkcs11.api.CKA_UNWRAP, ctpkcs11.api.CK_TRUE),
            (ctpkcs11.api.CKA_LABEL, label),
            (ctpkcs11.api.CKA_ID, key_id)
            #(ctpkcs11.api.CKA_SENSITIVE, ctpkcs11.api.CK_TRUE),
        ]

        self.session.generateKeyPair(public_template, private_template)

    def cert_save(self, cert, label, subject, key_id):
        cert_template = [
            (ctpkcs11.api.CKA_CLASS, ctpkcs11.api.CKO_CERTIFICATE),
            (ctpkcs11.api.CKA_CERTIFICATE_TYPE, ctpkcs11.api.CKC_X_509),
            (ctpkcs11.api.CKA_TOKEN, ctpkcs11.api.CK_TRUE),
            (ctpkcs11.api.CKA_LABEL, label),
            (
                ctpkcs11.api.CKA_ID,
                key_id,
            ),  # must be set, and DER see Table 24, X.509 Certificate Object Attributes
            (
                ctpkcs11.api.CKA_SUBJECT,
                subject.encode('utf8'),
            ),  # must be set and DER, see Table 24, X.509 Certificate Object Attributes
            # (ctpkcs11.api.CKA_PRIVATE, ctpkcs11.api.CK_FALSE),
            # (ctpkcs11.api.CKA_TRUSTED, ctpkcs11.api.CK_TRUE),
            # (ctpkcs11.api.CKA_SENSITIVE, ctpkcs11.api.CK_FALSE),
            # (ctpkcs11.api.CKA_ENCRYPT, ctpkcs11.api.CK_TRUE),
            # (ctpkcs11.api.CKA_VERIFY, ctpkcs11.api.CK_TRUE),
            # (ctpkcs11.api.CKA_MODIFIABLE, ctpkcs11.api.CK_TRUE),
            #            (ctpkcs11.api.CKA_ISSUER, cert.Issuer);
            #            (ctpkcs11.api.CKA_SERIAL_NUMBER,cert.SerialNumber)
            (ctpkcs11.api.CKA_VALUE, cert),  # must be BER-encoded
        ]

        self.session.createObject(cert_template)

    def cert_load(self, keyID):
        rec = self.session.findObjects([
            (ctpkcs11.api.CKA_CLASS, ctpkcs11.api.CKO_CERTIFICATE),
            (ctpkcs11.api.CKA_ID, keyID)
        ])
        if len(rec) != 1:
            return None
        cert = self.session.getAttributeValue(rec[0], [ctpkcs11.api.CKA_VALUE])[0]
        return cert

    def certsign(self, sn, pubKey, subject, until, caprivKey, ca):
        args = {
            "version": "v1",
            "serial_number": sn,
            "issuer": asn1x509.Name.build(
                {
                    "common_name": "hsm CA",
                }
            ),
            "subject": asn1x509.Name.build(
                {
                    "common_name": subject,
                }
            ),
            "signature": {
                "algorithm": "sha256_rsa",
                "parameters": None,
            },
            "validity": {
                "not_before": asn1x509.Time(
                    {
                        "utc_time": datetime.datetime.now(tz=asn1util.timezone.utc)
                        - datetime.timedelta(days=1),
                    }
                ),
                "not_after": asn1x509.Time(
                    {
                        "utc_time": until,
                    }
                ),
            },
            "subject_public_key_info": {
                "algorithm": {
                    "algorithm": "rsa",
                    "parameters": None,
                },
                "public_key": pubKey,
            },
        }
        if ca:
            args.update(
                {
                    "extensions": [
                        {
                            "extn_id": "basic_constraints",
                            "critical": True,
                            "extn_value": {"ca": True, "path_len_constraint": None},
                        },
                        {
                            "extn_id": "key_usage",
                            "critical": True,
                            "extn_value": set(
                                [
                                    "crl_sign",
                                    "digital_signature",
                                    "key_cert_sign",
                                ]
                            ),
                        },
                    ]
                }
            )
        else:
            args.update(
                {
                    "extensions": [
                        {
                            "extn_id": "basic_constraints",
                            "critical": True,
                            "extn_value": {"ca": False},
                        },
                        {
                            "extn_id": "key_usage",
                            "critical": True,
                            "extn_value": set(
                                [
                                    "digital_signature",
                                    "key_agreement",
                                    "key_encipherment",
                                    "non_repudiation",
                                ]
                            ),
                        },
                    ]
                }
            )
        tbs = asn1x509.TbsCertificate(args)

        # Sign the TBS Certificate
        data = tbs.dump()
        value = self.session.sign(
            caprivKey, data, ctpkcs11.api.Mechanism(ctpkcs11.api.CKM_SHA256_RSA_PKCS)
        )
        value = bytes(bytearray(value))

        cert = asn1x509.Certificate(
            {
                "tbs_certificate": tbs,
                "signature_algorithm": {
                    "algorithm": "sha256_rsa",
                    "parameters": None,
                },
                "signature_value": value,
            }
        )
        return cert.dump()

    def ca_gen(self, label, keyID, subject):
        privKey = self.session.findObjects([
            (ctpkcs11.api.CKA_CLASS, ctpkcs11.api.CKO_PRIVATE_KEY),
            (ctpkcs11.api.CKA_ID, keyID)
        ])[0]
        pubKey = self.session.findObjects(
            [(ctpkcs11.api.CKA_CLASS, ctpkcs11.api.CKO_PUBLIC_KEY), (ctpkcs11.api.CKA_ID, keyID)]
        )[0]

        modulus = self.session.getAttributeValue(pubKey, [ctpkcs11.api.CKA_MODULUS])[0]
        modulus = binascii.hexlify(bytearray(modulus)).decode("utf-8")
        exponent = self.session.getAttributeValue(
            pubKey, [ctpkcs11.api.CKA_PUBLIC_EXPONENT]
        )[0]
        exponent = binascii.hexlify(bytearray(exponent)).decode("utf-8")
        pubKey = asn1keys.RSAPublicKey(
            {
                "modulus": int("0x" + modulus, 16),
                "public_exponent": int("0x" + exponent, 16),
            }
        )
        # pubKey = asn1keys.RSAPublicKey.load(pubKey.dump())
        until = datetime.datetime.now(tz=asn1util.timezone.utc) + datetime.timedelta(
            days=365 * 10
        )
        der_bytes = self.certsign(1, pubKey, subject, until, privKey, True)
        self.cert_save(der_bytes, label, subject, keyID)

    def ca_sign(self, keyID, label, sn, subject, days, cakeyID):
        caprivKey = self.session.findObjects(
            [(ctpkcs11.api.CKA_CLASS, ctpkcs11.api.CKO_PRIVATE_KEY), (ctpkcs11.api.CKA_ID, cakeyID)]
        )[0]

        pubKey = self.session.findObjects(
            [(ctpkcs11.api.CKA_CLASS, ctpkcs11.api.CKO_PUBLIC_KEY), (ctpkcs11.api.CKA_ID, keyID)]
        )[0]
        modulus = self.session.getAttributeValue(pubKey, [ctpkcs11.api.CKA_MODULUS])[0]
        modulus = binascii.hexlify(bytearray(modulus)).decode("utf-8")
        exponent = self.session.getAttributeValue(
            pubKey, [ctpkcs11.api.CKA_PUBLIC_EXPONENT]
        )[0]
        exponent = binascii.hexlify(bytearray(exponent)).decode("utf-8")
        pubKey = asn1keys.RSAPublicKey(
            {
                "modulus": int("0x" + modulus, 16),
                "public_exponent": int("0x" + exponent, 16),
            }
        )
        # pubKey = asn1keys.RSAPublicKey.load(pubKey.dump())
        until = datetime.datetime.now(tz=asn1util.timezone.utc) + datetime.timedelta(
            days=days
        )
        der_bytes = self.certsign(sn, pubKey, subject, until, caprivKey, False)
        self.cert_save(der_bytes, label, subject, keyID)

    def cert_export(self, fname, keyID):
        der_bytes = self.cert_load(keyID)
        pem_bytes = asn1pem.armor("CERTIFICATE", der_bytes)
        with open(fname + ".der", "wb") as fp:
            fp.write(der_bytes)
        with open(fname + ".pem", "wb") as fp:
            fp.write(pem_bytes)

class Signer(HSM):
    session = None

    def getSlot(self, label):
        slots = self.pkcs11.getSlotList(tokenPresent=True)
        for slot in slots:
            info = self.pkcs11.getTokenInfo(slot)
            if info.label == label:
                return slot
        return None

    def login(self, label, pin):
        slot = self.getSlot(label)
        if slot is None:
            raise IOError(2)
        self.session = self.pkcs11.openSession(slot)
        self.session.login(pin)

    def logout(self):
        if self.session is not None:
            self.session.logout()
            self.session.close()
            self.session = None

    def certificate(self, label, pin, keyid):
        self.login(label, pin)
        try:
            pk11objects = self.session.findObjects(
                [(ctpkcs11.api.CKA_CLASS, ctpkcs11.api.CKO_CERTIFICATE)]
            )
            all_attributes = [
                # ctpkcs11.api.CKA_SUBJECT,
                ctpkcs11.api.CKA_VALUE,
                # ctpkcs11.api.CKA_ISSUER,
                # ctpkcs11.api.CKA_CERTIFICATE_CATEGORY,
                # ctpkcs11.api.CKA_END_DATE,
                ctpkcs11.api.CKA_ID,
            ]

            for pk11object in pk11objects:
                try:
                    attributes = self.session.getAttributeValue(
                        pk11object, all_attributes
                    )
                except AssertionError:
                    continue

                attrDict = dict(list(zip(all_attributes, attributes)))
                cert = bytes(attrDict[ctpkcs11.api.CKA_VALUE])
                if keyid == bytes(attrDict[ctpkcs11.api.CKA_ID]):
                    return keyid, cert
        finally:
            self.logout()
        return None, None

    def sign(self, label, pin, keyid, data, smech):
        self.login(label, pin)
        try:
            privKey = self.session.findObjects([
                (ctpkcs11.api.CKA_CLASS, ctpkcs11.api.CKO_PRIVATE_KEY),
                (ctpkcs11.api.CKA_ID, keyid)
            ])[0]
            mech = ctpkcs11.api.Mechanism(getattr(ctpkcs11.api, smech))
            sig = self.session.sign(privKey, data, mech)
            return bytes(sig)
        finally:
            self.logout()

    def verify(self, label, pin, keyid, data, signature, smech):
        self.login(label, pin)
        try:
            pubKey = self.session.findObjects([
                (ctpkcs11.api.CKA_CLASS, ctpkcs11.api.CKO_PUBLIC_KEY),
                (ctpkcs11.api.CKA_ID, keyid)
            ])[0]
            mech = ctpkcs11.api.Mechanism(getattr(ctpkcs11.api, smech))
            ok = self.session.verify(pubKey, data, signature, mech)
            return ok
        finally:
            self.logout()

    def encrypt(self, label, pin, keyid, data, mech):
        self.login(label, pin)
        try:
            key = self.session.findObjects([
                (ctpkcs11.api.CKA_CLASS, ctpkcs11.api.CKO_PUBLIC_KEY),
                (ctpkcs11.api.CKA_ID, keyid)
            ])[0]
            edata = self.session.encrypt(key, data, mech)
            return bytes(edata)
        finally:
            self.logout()

    def decrypt(self, label, pin, keyid, data, mech):
        self.login(label, pin)
        try:
            key = self.session.findObjects([
                (ctpkcs11.api.CKA_CLASS, ctpkcs11.api.CKO_PRIVATE_KEY),
                (ctpkcs11.api.CKA_ID, keyid)
            ])[0]
            ddata = self.session.decrypt(key, data, mech)
            return bytes(ddata)
        finally:
            self.logout()
