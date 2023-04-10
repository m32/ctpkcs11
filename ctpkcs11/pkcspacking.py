import ctypes
from datetime import datetime
from struct import Struct
from . import pkcsapi

# (Pack Function, Unpack Function) functions
_bool = (Struct('?').pack, lambda v: Struct('?').unpack(v)[0])
_ulong = (Struct('L').pack, lambda v: Struct('L').unpack(v)[0])
_str = (lambda s: s.encode('utf-8'), lambda b: b.decode('utf-8'))
_date = (lambda s: s.strftime('%Y%m%d').encode('ascii'),
         lambda s: datetime.strptime(s.decode('ascii'), '%Y%m%d').date())
_bytes = (bytes, bytes)
# The PKCS#11 biginteger type is an array of bytes in network byte order.
# If you have an int type, wrap it in biginteger()
_biginteger = _bytes

attrpackinfo = {
    pkcsapi.CKA_ALWAYS_AUTHENTICATE: _bool,
    pkcsapi.CKA_ALWAYS_SENSITIVE: _bool,
    pkcsapi.CKA_APPLICATION: _str,
    pkcsapi.CKA_BASE: _biginteger,
    pkcsapi.CKA_CERTIFICATE_TYPE: _ulong,
    pkcsapi.CKA_CHECK_VALUE: _bytes,
    pkcsapi.CKA_CLASS: _ulong,
    pkcsapi.CKA_COEFFICIENT: _biginteger,
    pkcsapi.CKA_DECRYPT: _bool,
    pkcsapi.CKA_DERIVE: _bool,
    pkcsapi.CKA_EC_PARAMS: _bytes,
    pkcsapi.CKA_EC_POINT: _bytes,
    pkcsapi.CKA_ENCRYPT: _bool,
    pkcsapi.CKA_END_DATE: _date,
    pkcsapi.CKA_EXPONENT_1: _biginteger,
    pkcsapi.CKA_EXPONENT_2: _biginteger,
    pkcsapi.CKA_EXTRACTABLE: _bool,
    pkcsapi.CKA_HASH_OF_ISSUER_PUBLIC_KEY: _bytes,
    pkcsapi.CKA_HASH_OF_SUBJECT_PUBLIC_KEY: _bytes,
    pkcsapi.CKA_ID: _bytes,
    pkcsapi.CKA_ISSUER: _bytes,
    pkcsapi.CKA_KEY_GEN_MECHANISM: _ulong,
    pkcsapi.CKA_KEY_TYPE: _ulong,
    pkcsapi.CKA_LABEL: _str,
    pkcsapi.CKA_LOCAL: _bool,
    pkcsapi.CKA_MODIFIABLE: _bool,
    #pkcsapi.CKA_COPYABLE: _bool,
    pkcsapi.CKA_MODULUS: _biginteger,
    pkcsapi.CKA_MODULUS_BITS: _ulong,
    pkcsapi.CKA_NEVER_EXTRACTABLE: _bool,
    pkcsapi.CKA_OBJECT_ID: _bytes,
    pkcsapi.CKA_PRIME: _biginteger,
    pkcsapi.CKA_PRIME_BITS: _ulong,
    pkcsapi.CKA_PRIME_1: _biginteger,
    pkcsapi.CKA_PRIME_2: _biginteger,
    pkcsapi.CKA_PRIVATE: _bool,
    pkcsapi.CKA_PRIVATE_EXPONENT: _biginteger,
    pkcsapi.CKA_PUBLIC_EXPONENT: _biginteger,
    pkcsapi.CKA_SENSITIVE: _bool,
    pkcsapi.CKA_SERIAL_NUMBER: _bytes,
    pkcsapi.CKA_SIGN: _bool,
    pkcsapi.CKA_SIGN_RECOVER: _bool,
    pkcsapi.CKA_START_DATE: _date,
    pkcsapi.CKA_SUBJECT: _bytes,
    pkcsapi.CKA_SUBPRIME: _biginteger,
    #pkcsapi.CKA_SUBPRIME_BITS: _ulong,
    pkcsapi.CKA_TOKEN: _bool,
    pkcsapi.CKA_TRUSTED: _bool,
    pkcsapi.CKA_UNWRAP: _bool,
    pkcsapi.CKA_URL: _str,
    pkcsapi.CKA_VALUE: _biginteger,
    pkcsapi.CKA_VALUE_BITS: _ulong,
    pkcsapi.CKA_VALUE_LEN: _ulong,
    pkcsapi.CKA_VERIFY: _bool,
    pkcsapi.CKA_VERIFY_RECOVER: _bool,
    pkcsapi.CKA_WRAP: _bool,
    pkcsapi.CKA_WRAP_WITH_TRUSTED: _bool,
}

def pack(attrs):
    rattr = (pkcsapi.ck_attribute * len(attrs))()
    offsets = []
    buf = []
    offset = 0
    for i in range(len(attrs)):
        a, v = attrs[i]
        v = attrpackinfo[a][0](v)
        buf.append(v)
        offsets.append(offset)
        rattr[i].type = a
        rattr[i].value_len = len(v)
        offset += len(v)
    buf = b''.join(buf)
    buf = ctypes.create_string_buffer(buf)
    l = ctypes.addressof(buf)
    for i in range(len(rattr)):
        rattr[i].value = ctypes.cast(offsets[i]+l, ctypes.c_void_p)
    return rattr, buf

def unpack(attr):
    v = ctypes._string_at(attr.value, attr.value_len)
    v = attrpackinfo[attr.type][1](v)
    return v
