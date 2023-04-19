#
# http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html
#
""" pkcs11.h
   Copyright 2006, 2007 g10 Code GmbH
   Copyright 2006 Andreas Jellinghaus

   This file is free software; as a special exception the author gives
   unlimited permission to copy and/or distribute it, with or without
   modifications, as long as this notice is preserved.

   This file is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY, to the extent permitted by law; without even
   the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
   PURPOSE.  """

""" Please submit changes back to the Scute project at
   http://www.scute.org/ (or send them to marcus@g10code.com), so that
   they can be picked up by other projects from there as well.  """

""" This file is a modified implementation of the PKCS #11 standard by
   RSA Security Inc.  It is mostly a drop-in replacement, with the
   following change:

   This header file does not require any macro definitions by the user
   (like CK_DEFINE_FUNCTION etc).  In fact, it defines those macros
   for you (if useful, some are missing, let me know if you need
   more).

   There is an additional API available that does comply better to the
   GNU coding standard.  It can be switched on by defining
   CRYPTOKI_GNU before including this header file.  For this, the
   following changes are made to the specification:

   All structure types are changed to a "struct ck_foo" where CK_FOO
   is the type name in PKCS #11.

   All non-structure types are changed to ck_foo_t where CK_FOO is the
   lowercase version of the type name in PKCS #11.  The basic types
   (CK_ULONG et al.) are removed without substitute.

   All members of structures are modified in the following way: Type
   indication prefixes are removed, and underscore characters are
   inserted before words.  Then the result is lowercased.

   Note that function names are still in the original case, as they
   need for ABI compatibility.

   CK_FALSE, CK_TRUE and NULL_PTR are removed without substitute.  Use
   <stdbool.h>.

   If CRYPTOKI_COMPAT is defined before including this header file,
   then none of the API changes above take place, and the API is the
   one defined by the PKCS #11 standard.  """

# ifndef PKCS11_H
# define PKCS11_H 1

# if defined(__cplusplus)
# extern "C" {
# endif


""" The version of cryptoki we implement.  The revision is changed with
   each modification of this file.  If you do not use the "official"
   version of this file, please consider deleting the revision macro
   (you may use a macro with a different name to keep track of your
   versions).  """
CRYPTOKI_VERSION_MAJOR = 2
CRYPTOKI_VERSION_MINOR = 20
CRYPTOKI_VERSION_REVISION = 6


""" Compatibility interface is default, unless CRYPTOKI_GNU is
   given.  """
# ifndef CRYPTOKI_GNU
# ifndef CRYPTOKI_COMPAT
# define CRYPTOKI_COMPAT 1
# endif
# endif

""" System dependencies.  """

# if defined(_WIN32) || defined(CRYPTOKI_FORCE_WIN32)

""" There is a matching pop below.  """
# pragma pack(push, cryptoki, 1)

# ifdef CRYPTOKI_EXPORTS
# define CK_SPEC __declspec(dllexport)
# else
# define CK_SPEC __declspec(dllimport)
# endif

# else

# define CK_SPEC

# endif


# ifdef CRYPTOKI_COMPAT
""" If we are in compatibility mode, switch all exposed names to the
     PKCS #11 variant.  There are corresponding #undefs below.  """

# define ck_flags_t CK_FLAGS
# define ck_version _CK_VERSION

# define ck_info _CK_INFO
# define cryptoki_version cryptokiVersion
# define manufacturer_id manufacturerID
# define library_description libraryDescription
# define library_version libraryVersion

# define ck_notification_t CK_NOTIFICATION
# define ck_slot_id_t CK_SLOT_ID

# define ck_slot_info _CK_SLOT_INFO
# define slot_description slotDescription
# define hardware_version hardwareVersion
# define firmware_version firmwareVersion

# define ck_token_info _CK_TOKEN_INFO
# define serial_number serialNumber
# define max_session_count ulMaxSessionCount
# define session_count ulSessionCount
# define max_rw_session_count ulMaxRwSessionCount
# define rw_session_count ulRwSessionCount
# define max_pin_len ulMaxPinLen
# define min_pin_len ulMinPinLen
# define total_public_memory ulTotalPublicMemory
# define free_public_memory ulFreePublicMemory
# define total_private_memory ulTotalPrivateMemory
# define free_private_memory ulFreePrivateMemory
# define utc_time utcTime

# define ck_session_handle_t CK_SESSION_HANDLE
# define ck_user_type_t CK_USER_TYPE
# define ck_state_t CK_STATE

# define ck_session_info _CK_SESSION_INFO
# define slot_id slotID
# define device_error ulDeviceError

# define ck_object_handle_t CK_OBJECT_HANDLE
# define ck_object_class_t CK_OBJECT_CLASS
# define ck_hw_feature_type_t CK_HW_FEATURE_TYPE
# define ck_key_type_t CK_KEY_TYPE
# define ck_certificate_type_t CK_CERTIFICATE_TYPE
# define ck_attribute_type_t CK_ATTRIBUTE_TYPE

# define ck_attribute _CK_ATTRIBUTE
# define value pValue
# define value_len ulValueLen

# define ck_date _CK_DATE

# define ck_mechanism_type_t CK_MECHANISM_TYPE

# define ck_mechanism _CK_MECHANISM
# define parameter pParameter
# define parameter_len ulParameterLen

# define ck_mechanism_info _CK_MECHANISM_INFO
# define min_key_size ulMinKeySize
# define max_key_size ulMaxKeySize

# define ck_rsa_pkcs_oaep_params _CK_RSA_PCKS_OAEP_PARAMS
# define source_data pSourceData
# define source_data_len ulSourceDataLen

# define ck_rv_t CK_RV
# define ck_notify_t CK_NOTIFY

# define ck_function_list _CK_FUNCTION_LIST

# define ck_createmutex_t CK_CREATEMUTEX
# define ck_destroymutex_t CK_DESTROYMUTEX
# define ck_lockmutex_t CK_LOCKMUTEX
# define ck_unlockmutex_t CK_UNLOCKMUTEX

# define ck_c_initialize_args _CK_C_INITIALIZE_ARGS
# define create_mutex CreateMutex
# define destroy_mutex DestroyMutex
# define lock_mutex LockMutex
# define unlock_mutex UnlockMutex
# define reserved pReserved

# endif	''' CRYPTOKI_COMPAT '''

import io
from ctypes import (
    c_char,
    c_ubyte,
    c_int,
    c_uint,
    c_long,
    c_ulong,
    POINTER,
    c_void_p,
    Structure,
    CFUNCTYPE,
    sizeof,
    addressof,
    byref,
    create_string_buffer,
)

c_ubyte_p = POINTER(c_ubyte)
c_int_p = POINTER(c_int)
c_uint_p = POINTER(c_uint)
c_long_p = POINTER(c_long)
c_ulong_p = POINTER(c_ulong)

aliases = {}


def parseline(cdef):
    #print(cdef)
    if cdef[0] == "struct":
        # struct <typename> [*] varname;
        ctype = aliases[cdef[1]]
        cdef = cdef[2:]
    elif cdef[0] == "unsigned":
        # unsigned [char|int|long int] [*] <varname>;
        t = {"char": c_ubyte, "int": c_uint, "long": c_ulong}
        ctype = t[cdef[1]]
        if cdef[1] == "long" and cdef[2] == "int":
            cdef = cdef[3:]
        else:
            cdef = cdef[2:]
    else:
        try:
            ctype = aliases[cdef[0]]
        except KeyError:
            if cdef[0] == "void":
                # void * <varname>
                cdef = "".join(cdef[1:])
                assert cdef[0] == "*"
                cdef = ['*', cdef[1:]]
                ctype = c_void_p
            else:
                # [char|int|long] * <varname>
                t = {"char": c_char, "int": c_int, "long": c_long}
                ctype = t[cdef[0]]
        cdef = cdef[1:]
    cdef = "".join(cdef)
    assert cdef != ''
    while cdef and cdef[0] == "*":
        cdef = cdef[1:]
        ctype = POINTER(ctype)
    if "[" in cdef:
        cdef = cdef.split("[")
        name = cdef[0]
        size = int(cdef[1][:-1])
        ctype *= size
    else:
        name = cdef
    return name, ctype


def ctypedef(cdef):
    cdef = cdef.strip()[:-1].split()
    assert cdef[0] == "typedef"
    name, ctype = parseline(cdef[1:])
    aliases[name] = ctype
    return ctype


def cstruct(cdef):
    struct_name, _, cdef = cdef.partition("{")
    struct_name = struct_name.strip().split()[1]
    cdef = cdef.partition("}")[0]
    lines = io.StringIO(cdef.strip()).readlines()
    fields = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        cdef = line[:-1].split()
        name, ctype = parseline(cdef)
        fields.append((name, ctype))

    class CStruct(Structure):
        _fields_ = fields

        def __repr__(self):
            return "{0}({1})".format(
                struct_name,
                ", ".join([k + "=" + repr(getattr(self, k)) for k, t in self._fields_]),
            )

    aliases[struct_name] = CStruct

    return CStruct


ck_flags_t = ctypedef("typedef unsigned long ck_flags_t;")

ck_version = cstruct(
    """
struct ck_version
{
  unsigned char major;
  unsigned char minor;
};
"""
)

ck_info = cstruct(
    """
struct ck_info
{
  struct ck_version cryptoki_version;
  unsigned char manufacturer_id[32];
  ck_flags_t flags;
  unsigned char library_description[32];
  struct ck_version library_version;
};
"""
)

ck_notification_t = ctypedef("typedef unsigned long ck_notification_t")

CKN_SURRENDER = 0


ck_slot_id_t = ctypedef("typedef unsigned long ck_slot_id_t;")


ck_slot_info = cstruct(
    """
struct ck_slot_info
{
  unsigned char slot_description[64];
  unsigned char manufacturer_id[32];
  ck_flags_t flags;
  struct ck_version hardware_version;
  struct ck_version firmware_version;
};
"""
)


CKF_TOKEN_PRESENT = 1 << 0
CKF_REMOVABLE_DEVICE = 1 << 1
CKF_HW_SLOT = 1 << 2
CKF_ARRAY_ATTRIBUTE = 1 << 30


ck_token_info = cstruct(
    """
struct ck_token_info
{
  unsigned char label[32];
  unsigned char manufacturer_id[32];
  unsigned char model[16];
  unsigned char serial_number[16];
  ck_flags_t flags;
  unsigned long max_session_count;
  unsigned long session_count;
  unsigned long max_rw_session_count;
  unsigned long rw_session_count;
  unsigned long max_pin_len;
  unsigned long min_pin_len;
  unsigned long total_public_memory;
  unsigned long free_public_memory;
  unsigned long total_private_memory;
  unsigned long free_private_memory;
  struct ck_version hardware_version;
  struct ck_version firmware_version;
  unsigned char utc_time[16];
};
"""
)

CKF_RNG = 1 << 0
CKF_WRITE_PROTECTED = 1 << 1
CKF_LOGIN_REQUIRED = 1 << 2
CKF_USER_PIN_INITIALIZED = 1 << 3
CKF_RESTORE_KEY_NOT_NEEDED = 1 << 5
CKF_CLOCK_ON_TOKEN = 1 << 6
CKF_PROTECTED_AUTHENTICATION_PATH = 1 << 8
CKF_DUAL_CRYPTO_OPERATIONS = 1 << 9
CKF_TOKEN_INITIALIZED = 1 << 10
CKF_SECONDARY_AUTHENTICATION = 1 << 11
CKF_USER_PIN_COUNT_LOW = 1 << 16
CKF_USER_PIN_FINAL_TRY = 1 << 17
CKF_USER_PIN_LOCKED = 1 << 18
CKF_USER_PIN_TO_BE_CHANGED = 1 << 19
CKF_SO_PIN_COUNT_LOW = 1 << 20
CKF_SO_PIN_FINAL_TRY = 1 << 21
CKF_SO_PIN_LOCKED = 1 << 22
CKF_SO_PIN_TO_BE_CHANGED = 1 << 23

CK_UNAVAILABLE_INFORMATION = -1
CK_EFFECTIVELY_INFINITE = 0


ck_session_handle_t = ctypedef("typedef unsigned long ck_session_handle_t;")

CK_INVALID_HANDLE = 0


ck_user_type_t = ctypedef("typedef unsigned long ck_user_type_t;")

CKU_SO = 0
CKU_USER = 1
CKU_CONTEXT_SPECIFIC = 2


ck_state_t = ctypedef("typedef unsigned long ck_state_t;")

CKS_RO_PUBLIC_SESSION = 0
CKS_RO_USER_FUNCTIONS = 1
CKS_RW_PUBLIC_SESSION = 2
CKS_RW_USER_FUNCTIONS = 3
CKS_RW_SO_FUNCTIONS = 4


ck_session_info = cstruct(
    """
struct ck_session_info
{
  ck_slot_id_t slot_id;
  ck_state_t state;
  ck_flags_t flags;
  unsigned long device_error;
};
"""
)

CKF_RW_SESSION = 1 << 1
CKF_SERIAL_SESSION = 1 << 2


ck_object_handle_t = ctypedef("typedef unsigned long ck_object_handle_t;")


ck_object_class_t = ctypedef("typedef unsigned long ck_object_class_t;")

CKO_DATA = 0
CKO_CERTIFICATE = 1
CKO_PUBLIC_KEY = 2
CKO_PRIVATE_KEY = 3
CKO_SECRET_KEY = 4
CKO_HW_FEATURE = 5
CKO_DOMAIN_PARAMETERS = 6
CKO_MECHANISM = 7
CKO_VENDOR_DEFINED = 1 << 31


ck_hw_feature_type_t = ctypedef("typedef unsigned long ck_hw_feature_type_t;")

CKH_MONOTONIC_COUNTER = 1
CKH_CLOCK = 2
CKH_USER_INTERFACE = 3
CKH_VENDOR_DEFINED = 1 << 31


ck_key_type_t = ctypedef("typedef unsigned long ck_key_type_t;")

CKK_RSA = 0
CKK_DSA = 1
CKK_DH = 2
CKK_ECDSA = 3
CKK_EC = 3
CKK_X9_42_DH = 4
CKK_KEA = 5
CKK_GENERIC_SECRET = 0x10
CKK_RC2 = 0x11
CKK_RC4 = 0x12
CKK_DES = 0x13
CKK_DES2 = 0x14
CKK_DES3 = 0x15
CKK_CAST = 0x16
CKK_CAST3 = 0x17
CKK_CAST128 = 0x18
CKK_RC5 = 0x19
CKK_IDEA = 0x1A
CKK_SKIPJACK = 0x1B
CKK_BATON = 0x1C
CKK_JUNIPER = 0x1D
CKK_CDMF = 0x1E
CKK_AES = 0x1F
CKK_BLOWFISH = 0x20
CKK_TWOFISH = 0x21
CKK_VENDOR_DEFINED = 1 << 31

ck_certificate_type_t = ctypedef("typedef unsigned long ck_certificate_type_t;")

CKC_X_509 = 0
CKC_X_509_ATTR_CERT = 1
CKC_WTLS = 2
CKC_VENDOR_DEFINED = 1 << 31


ck_attribute_type_t = ctypedef("typedef unsigned long ck_attribute_type_t;")

CKA_CLASS = 0
CKA_TOKEN = 1
CKA_PRIVATE = 2
CKA_LABEL = 3
CKA_APPLICATION = 0x10
CKA_VALUE = 0x11
CKA_OBJECT_ID = 0x12
CKA_CERTIFICATE_TYPE = 0x80
CKA_ISSUER = 0x81
CKA_SERIAL_NUMBER = 0x82
CKA_AC_ISSUER = 0x83
CKA_OWNER = 0x84
CKA_ATTR_TYPES = 0x85
CKA_TRUSTED = 0x86
CKA_CERTIFICATE_CATEGORY = 0x87
CKA_JAVA_MIDP_SECURITY_DOMAIN = 0x88
CKA_URL = 0x89
CKA_HASH_OF_SUBJECT_PUBLIC_KEY = 0x8A
CKA_HASH_OF_ISSUER_PUBLIC_KEY = 0x8B
CKA_CHECK_VALUE = 0x90
CKA_KEY_TYPE = 0x100
CKA_SUBJECT = 0x101
CKA_ID = 0x102
CKA_SENSITIVE = 0x103
CKA_ENCRYPT = 0x104
CKA_DECRYPT = 0x105
CKA_WRAP = 0x106
CKA_UNWRAP = 0x107
CKA_SIGN = 0x108
CKA_SIGN_RECOVER = 0x109
CKA_VERIFY = 0x10A
CKA_VERIFY_RECOVER = 0x10B
CKA_DERIVE = 0x10C
CKA_START_DATE = 0x110
CKA_END_DATE = 0x111
CKA_MODULUS = 0x120
CKA_MODULUS_BITS = 0x121
CKA_PUBLIC_EXPONENT = 0x122
CKA_PRIVATE_EXPONENT = 0x123
CKA_PRIME_1 = 0x124
CKA_PRIME_2 = 0x125
CKA_EXPONENT_1 = 0x126
CKA_EXPONENT_2 = 0x127
CKA_COEFFICIENT = 0x128
CKA_PRIME = 0x130
CKA_SUBPRIME = 0x131
CKA_BASE = 0x132
CKA_PRIME_BITS = 0x133
CKA_SUB_PRIME_BITS = 0x134
CKA_VALUE_BITS = 0x160
CKA_VALUE_LEN = 0x161
CKA_EXTRACTABLE = 0x162
CKA_LOCAL = 0x163
CKA_NEVER_EXTRACTABLE = 0x164
CKA_ALWAYS_SENSITIVE = 0x165
CKA_KEY_GEN_MECHANISM = 0x166
CKA_MODIFIABLE = 0x170
CKA_ECDSA_PARAMS = 0x180
CKA_EC_PARAMS = 0x180
CKA_EC_POINT = 0x181
CKA_SECONDARY_AUTH = 0x200
CKA_AUTH_PIN_FLAGS = 0x201
CKA_ALWAYS_AUTHENTICATE = 0x202
CKA_WRAP_WITH_TRUSTED = 0x210
CKA_HW_FEATURE_TYPE = 0x300
CKA_RESET_ON_INIT = 0x301
CKA_HAS_RESET = 0x302
CKA_PIXEL_X = 0x400
CKA_PIXEL_Y = 0x401
CKA_RESOLUTION = 0x402
CKA_CHAR_ROWS = 0x403
CKA_CHAR_COLUMNS = 0x404
CKA_COLOR = 0x405
CKA_BITS_PER_PIXEL = 0x406
CKA_CHAR_SETS = 0x480
CKA_ENCODING_METHODS = 0x481
CKA_MIME_TYPES = 0x482
CKA_MECHANISM_TYPE = 0x500
CKA_REQUIRED_CMS_ATTRIBUTES = 0x501
CKA_DEFAULT_CMS_ATTRIBUTES = 0x502
CKA_SUPPORTED_CMS_ATTRIBUTES = 0x503
CKA_WRAP_TEMPLATE = CKF_ARRAY_ATTRIBUTE | 0x211
CKA_UNWRAP_TEMPLATE = CKF_ARRAY_ATTRIBUTE | 0x212
CKA_ALLOWED_MECHANISMS = CKF_ARRAY_ATTRIBUTE | 0x600
CKA_VENDOR_DEFINED = 1 << 31


ck_attribute = cstruct(
    """
struct ck_attribute
{
  ck_attribute_type_t type;
  void *value;
  unsigned long value_len;
};
"""
)


ck_date = cstruct(
    """
struct ck_date
{
  unsigned char year[4];
  unsigned char month[2];
  unsigned char day[2];
};
"""
)


ck_mechanism_type_t = ctypedef("typedef unsigned long ck_mechanism_type_t;")

CKM_RSA_PKCS_KEY_PAIR_GEN = 0
CKM_RSA_PKCS = 1
CKM_RSA_9796 = 2
CKM_RSA_X_509 = 3
CKM_MD2_RSA_PKCS = 4
CKM_MD5_RSA_PKCS = 5
CKM_SHA1_RSA_PKCS = 6
CKM_RIPEMD128_RSA_PKCS = 7
CKM_RIPEMD160_RSA_PKCS = 8
CKM_RSA_PKCS_OAEP = 9
CKM_RSA_X9_31_KEY_PAIR_GEN = 0xA
CKM_RSA_X9_31 = 0xB
CKM_SHA1_RSA_X9_31 = 0xC
CKM_RSA_PKCS_PSS = 0xD
CKM_SHA1_RSA_PKCS_PSS = 0xE
CKM_DSA_KEY_PAIR_GEN = 0x10
CKM_DSA = 0x11
CKM_DSA_SHA1 = 0x12
CKM_DH_PKCS_KEY_PAIR_GEN = 0x20
CKM_DH_PKCS_DERIVE = 0x21
CKM_X9_42_DH_KEY_PAIR_GEN = 0x30
CKM_X9_42_DH_DERIVE = 0x31
CKM_X9_42_DH_HYBRID_DERIVE = 0x32
CKM_X9_42_MQV_DERIVE = 0x33
CKM_SHA256_RSA_PKCS = 0x40
CKM_SHA384_RSA_PKCS = 0x41
CKM_SHA512_RSA_PKCS = 0x42
CKM_SHA256_RSA_PKCS_PSS = 0x43
CKM_SHA384_RSA_PKCS_PSS = 0x44
CKM_SHA512_RSA_PKCS_PSS = 0x45
CKM_RC2_KEY_GEN = 0x100
CKM_RC2_ECB = 0x101
CKM_RC2_CBC = 0x102
CKM_RC2_MAC = 0x103
CKM_RC2_MAC_GENERAL = 0x104
CKM_RC2_CBC_PAD = 0x105
CKM_RC4_KEY_GEN = 0x110
CKM_RC4 = 0x111
CKM_DES_KEY_GEN = 0x120
CKM_DES_ECB = 0x121
CKM_DES_CBC = 0x122
CKM_DES_MAC = 0x123
CKM_DES_MAC_GENERAL = 0x124
CKM_DES_CBC_PAD = 0x125
CKM_DES2_KEY_GEN = 0x130
CKM_DES3_KEY_GEN = 0x131
CKM_DES3_ECB = 0x132
CKM_DES3_CBC = 0x133
CKM_DES3_MAC = 0x134
CKM_DES3_MAC_GENERAL = 0x135
CKM_DES3_CBC_PAD = 0x136
CKM_CDMF_KEY_GEN = 0x140
CKM_CDMF_ECB = 0x141
CKM_CDMF_CBC = 0x142
CKM_CDMF_MAC = 0x143
CKM_CDMF_MAC_GENERAL = 0x144
CKM_CDMF_CBC_PAD = 0x145
CKM_MD2 = 0x200
CKM_MD2_HMAC = 0x201
CKM_MD2_HMAC_GENERAL = 0x202
CKM_MD5 = 0x210
CKM_MD5_HMAC = 0x211
CKM_MD5_HMAC_GENERAL = 0x212
CKM_SHA_1 = 0x220
CKM_SHA_1_HMAC = 0x221
CKM_SHA_1_HMAC_GENERAL = 0x222
CKM_RIPEMD128 = 0x230
CKM_RIPEMD128_HMAC = 0x231
CKM_RIPEMD128_HMAC_GENERAL = 0x232
CKM_RIPEMD160 = 0x240
CKM_RIPEMD160_HMAC = 0x241
CKM_RIPEMD160_HMAC_GENERAL = 0x242
CKM_SHA256 = 0x250
CKM_SHA256_HMAC = 0x251
CKM_SHA256_HMAC_GENERAL = 0x252
CKM_SHA384 = 0x260
CKM_SHA384_HMAC = 0x261
CKM_SHA384_HMAC_GENERAL = 0x262
CKM_SHA512 = 0x270
CKM_SHA512_HMAC = 0x271
CKM_SHA512_HMAC_GENERAL = 0x272
CKM_CAST_KEY_GEN = 0x300
CKM_CAST_ECB = 0x301
CKM_CAST_CBC = 0x302
CKM_CAST_MAC = 0x303
CKM_CAST_MAC_GENERAL = 0x304
CKM_CAST_CBC_PAD = 0x305
CKM_CAST3_KEY_GEN = 0x310
CKM_CAST3_ECB = 0x311
CKM_CAST3_CBC = 0x312
CKM_CAST3_MAC = 0x313
CKM_CAST3_MAC_GENERAL = 0x314
CKM_CAST3_CBC_PAD = 0x315
CKM_CAST5_KEY_GEN = 0x320
CKM_CAST128_KEY_GEN = 0x320
CKM_CAST5_ECB = 0x321
CKM_CAST128_ECB = 0x321
CKM_CAST5_CBC = 0x322
CKM_CAST128_CBC = 0x322
CKM_CAST5_MAC = 0x323
CKM_CAST128_MAC = 0x323
CKM_CAST5_MAC_GENERAL = 0x324
CKM_CAST128_MAC_GENERAL = 0x324
CKM_CAST5_CBC_PAD = 0x325
CKM_CAST128_CBC_PAD = 0x325
CKM_RC5_KEY_GEN = 0x330
CKM_RC5_ECB = 0x331
CKM_RC5_CBC = 0x332
CKM_RC5_MAC = 0x333
CKM_RC5_MAC_GENERAL = 0x334
CKM_RC5_CBC_PAD = 0x335
CKM_IDEA_KEY_GEN = 0x340
CKM_IDEA_ECB = 0x341
CKM_IDEA_CBC = 0x342
CKM_IDEA_MAC = 0x343
CKM_IDEA_MAC_GENERAL = 0x344
CKM_IDEA_CBC_PAD = 0x345
CKM_GENERIC_SECRET_KEY_GEN = 0x350
CKM_CONCATENATE_BASE_AND_KEY = 0x360
CKM_CONCATENATE_BASE_AND_DATA = 0x362
CKM_CONCATENATE_DATA_AND_BASE = 0x363
CKM_XOR_BASE_AND_DATA = 0x364
CKM_EXTRACT_KEY_FROM_KEY = 0x365
CKM_SSL3_PRE_MASTER_KEY_GEN = 0x370
CKM_SSL3_MASTER_KEY_DERIVE = 0x371
CKM_SSL3_KEY_AND_MAC_DERIVE = 0x372
CKM_SSL3_MASTER_KEY_DERIVE_DH = 0x373
CKM_TLS_PRE_MASTER_KEY_GEN = 0x374
CKM_TLS_MASTER_KEY_DERIVE = 0x375
CKM_TLS_KEY_AND_MAC_DERIVE = 0x376
CKM_TLS_MASTER_KEY_DERIVE_DH = 0x377
CKM_SSL3_MD5_MAC = 0x380
CKM_SSL3_SHA1_MAC = 0x381
CKM_MD5_KEY_DERIVATION = 0x390
CKM_MD2_KEY_DERIVATION = 0x391
CKM_SHA1_KEY_DERIVATION = 0x392
CKM_PBE_MD2_DES_CBC = 0x3A0
CKM_PBE_MD5_DES_CBC = 0x3A1
CKM_PBE_MD5_CAST_CBC = 0x3A2
CKM_PBE_MD5_CAST3_CBC = 0x3A3
CKM_PBE_MD5_CAST5_CBC = 0x3A4
CKM_PBE_MD5_CAST128_CBC = 0x3A4
CKM_PBE_SHA1_CAST5_CBC = 0x3A5
CKM_PBE_SHA1_CAST128_CBC = 0x3A5
CKM_PBE_SHA1_RC4_128 = 0x3A6
CKM_PBE_SHA1_RC4_40 = 0x3A7
CKM_PBE_SHA1_DES3_EDE_CBC = 0x3A8
CKM_PBE_SHA1_DES2_EDE_CBC = 0x3A9
CKM_PBE_SHA1_RC2_128_CBC = 0x3AA
CKM_PBE_SHA1_RC2_40_CBC = 0x3AB
CKM_PKCS5_PBKD2 = 0x3B0
CKM_PBA_SHA1_WITH_SHA1_HMAC = 0x3C0
CKM_KEY_WRAP_LYNKS = 0x400
CKM_KEY_WRAP_SET_OAEP = 0x401
CKM_SKIPJACK_KEY_GEN = 0x1000
CKM_SKIPJACK_ECB64 = 0x1001
CKM_SKIPJACK_CBC64 = 0x1002
CKM_SKIPJACK_OFB64 = 0x1003
CKM_SKIPJACK_CFB64 = 0x1004
CKM_SKIPJACK_CFB32 = 0x1005
CKM_SKIPJACK_CFB16 = 0x1006
CKM_SKIPJACK_CFB8 = 0x1007
CKM_SKIPJACK_WRAP = 0x1008
CKM_SKIPJACK_PRIVATE_WRAP = 0x1009
CKM_SKIPJACK_RELAYX = 0x100A
CKM_KEA_KEY_PAIR_GEN = 0x1010
CKM_KEA_KEY_DERIVE = 0x1011
CKM_FORTEZZA_TIMESTAMP = 0x1020
CKM_BATON_KEY_GEN = 0x1030
CKM_BATON_ECB128 = 0x1031
CKM_BATON_ECB96 = 0x1032
CKM_BATON_CBC128 = 0x1033
CKM_BATON_COUNTER = 0x1034
CKM_BATON_SHUFFLE = 0x1035
CKM_BATON_WRAP = 0x1036
CKM_ECDSA_KEY_PAIR_GEN = 0x1040
CKM_EC_KEY_PAIR_GEN = 0x1040
CKM_ECDSA = 0x1041
CKM_ECDSA_SHA1 = 0x1042
CKM_ECDH1_DERIVE = 0x1050
CKM_ECDH1_COFACTOR_DERIVE = 0x1051
CKM_ECMQV_DERIVE = 0x1052
CKM_JUNIPER_KEY_GEN = 0x1060
CKM_JUNIPER_ECB128 = 0x1061
CKM_JUNIPER_CBC128 = 0x1062
CKM_JUNIPER_COUNTER = 0x1063
CKM_JUNIPER_SHUFFLE = 0x1064
CKM_JUNIPER_WRAP = 0x1065
CKM_FASTHASH = 0x1070
CKM_AES_KEY_GEN = 0x1080
CKM_AES_ECB = 0x1081
CKM_AES_CBC = 0x1082
CKM_AES_MAC = 0x1083
CKM_AES_MAC_GENERAL = 0x1084
CKM_AES_CBC_PAD = 0x1085
CKM_DSA_PARAMETER_GEN = 0x2000
CKM_DH_PKCS_PARAMETER_GEN = 0x2001
CKM_X9_42_DH_PARAMETER_GEN = 0x2002
CKM_VENDOR_DEFINED = 1 << 31

CKM_SHA224 = 0x255
CKM_SHA224_HMAC = 0x256
CKM_SHA224_HMAC_GENERAL = 0x257
CKM_SHA224_RSA_PKCS = 0x46
CKM_SHA224_RSA_PKCS_PSS = 0x47
CKM_SHA224_KEY_DERIVATION = 0x396

CKM_CAMELLIA_KEY_GEN = 0x550
CKM_CAMELLIA_ECB = 0x551
CKM_CAMELLIA_CBC = 0x552
CKM_CAMELLIA_MAC = 0x553
CKM_CAMELLIA_MAC_GENERAL = 0x554
CKM_CAMELLIA_CBC_PAD = 0x555
CKM_CAMELLIA_ECB_ENCRYPT_DATA = 0x556
CKM_CAMELLIA_CBC_ENCRYPT_DATA = 0x557

CKM_AES_KEY_WRAP = 0x2109
CKM_AES_KEY_WRAP_PAD = 0x210a

CKM_RSA_PKCS_TPM_1_1 = 0x4001
CKM_RSA_PKCS_OAEP_TPM_1_1 = 0x4002

CKM_EC_EDWARDS_KEY_PAIR_GEN = 0x1055
CKM_EDDSA = 0x1057

CKG_MGF1_SHA1 = 0x00000001
CKG_MGF1_SHA256 = 0x00000002
CKG_MGF1_SHA384 = 0x00000003
CKG_MGF1_SHA512 = 0x00000004


ck_mechanism = cstruct(
    """
struct ck_mechanism
{
  ck_mechanism_type_t mechanism;
  void *parameter;
  unsigned long parameter_len;
};
"""
)

ck_mechanism_info = cstruct(
    """
struct ck_mechanism_info
{
  unsigned long min_key_size;
  unsigned long max_key_size;
  ck_flags_t flags;
};
"""
)

ck_rsa_pkcs_oaep_params = cstruct(
    """
struct ck_rsa_pkcs_oaep_params
{
  unsigned long hashAlg;
  unsigned long mgf;
  unsigned long src;
  void *source_data;
  unsigned long source_data_len;
};
"""
)

ck_rsa_pkcs_pss_params = cstruct(
    """
struct ck_rsa_pkcs_pss_params
{
  unsigned long hashAlg;
  unsigned long mgf;
  unsigned long sLen;
};
"""
)

ck_gcm_params = cstruct(
    """
struct ck_gcm_params
{
  void *pIv;
  unsigned long ulIvLen;
  unsigned long ulIvBits;
  void *pAAD;
  unsigned long ulAADLen;
  unsigned long ulTagBits;
};
"""
)
ck_ecdh1_derive_params = cstruct(
    """
struct ck_ecdh1_derive_params {
  unsigned long kdf;
  unsigned long ulSharedDataLen;
  void * pSharedData;
  unsigned long ulPublicDataLen;
  void * pPublicData;
};
"""
)                             

CKF_HW = 1 << 0
CKF_ENCRYPT = 1 << 8
CKF_DECRYPT = 1 << 9
CKF_DIGEST = 1 << 10
CKF_SIGN = 1 << 11
CKF_SIGN_RECOVER = 1 << 12
CKF_VERIFY = 1 << 13
CKF_VERIFY_RECOVER = 1 << 14
CKF_GENERATE = 1 << 15
CKF_GENERATE_KEY_PAIR = 1 << 16
CKF_WRAP = 1 << 17
CKF_UNWRAP = 1 << 18
CKF_DERIVE = 1 << 19
CKF_EXTENSION = 1 << 31


""" Flags for C_WaitForSlotEvent.  """
CKF_DONT_BLOCK = 1


ck_rv_t = ctypedef("typedef unsigned long ck_rv_t;")

ck_notify_t = CFUNCTYPE(ck_rv_t, ck_session_handle_t, ck_notification_t, c_void_p)
aliases['ck_notify_t'] = ck_notify_t

"""

typedef ck_rv_t (*ck_notify_t) (ck_session_handle_t session,
				ck_notification_t event, void *application);
"""

""" Forward reference.  """
"""
struct ck_function_list;

#define _CK_DECLARE_FUNCTION(name, args)	\
typedef ck_rv_t (*CK_ ## name) args;		\
ck_rv_t CK_SPEC name args

_CK_DECLARE_FUNCTION (C_Initialize, (void *init_args));
_CK_DECLARE_FUNCTION (C_Finalize, (void *reserved));
_CK_DECLARE_FUNCTION (C_GetInfo, (struct ck_info *info));
_CK_DECLARE_FUNCTION (C_GetFunctionList,
		      (struct ck_function_list **function_list));

_CK_DECLARE_FUNCTION (C_GetSlotList,
		      (unsigned char token_present, ck_slot_id_t *slot_list,
		       unsigned long *count));
_CK_DECLARE_FUNCTION (C_GetSlotInfo,
		      (ck_slot_id_t slot_id, struct ck_slot_info *info));
_CK_DECLARE_FUNCTION (C_GetTokenInfo,
		      (ck_slot_id_t slot_id, struct ck_token_info *info));
_CK_DECLARE_FUNCTION (C_WaitForSlotEvent,
		      (ck_flags_t flags, ck_slot_id_t *slot, void *reserved));
_CK_DECLARE_FUNCTION (C_GetMechanismList,
		      (ck_slot_id_t slot_id,
		       ck_mechanism_type_t *mechanism_list,
		       unsigned long *count));
_CK_DECLARE_FUNCTION (C_GetMechanismInfo,
		      (ck_slot_id_t slot_id, ck_mechanism_type_t type,
		       struct ck_mechanism_info *info));
_CK_DECLARE_FUNCTION (C_InitToken,
		      (ck_slot_id_t slot_id, unsigned char *pin,
		       unsigned long pin_len, unsigned char *label));
_CK_DECLARE_FUNCTION (C_InitPIN,
		      (ck_session_handle_t session, unsigned char *pin,
		       unsigned long pin_len));
_CK_DECLARE_FUNCTION (C_SetPIN,
		      (ck_session_handle_t session, unsigned char *old_pin,
		       unsigned long old_len, unsigned char *new_pin,
		       unsigned long new_len));

_CK_DECLARE_FUNCTION (C_OpenSession,
		      (ck_slot_id_t slot_id, ck_flags_t flags,
		       void *application, ck_notify_t notify,
		       ck_session_handle_t *session));
_CK_DECLARE_FUNCTION (C_CloseSession, (ck_session_handle_t session));
_CK_DECLARE_FUNCTION (C_CloseAllSessions, (ck_slot_id_t slot_id));
_CK_DECLARE_FUNCTION (C_GetSessionInfo,
		      (ck_session_handle_t session,
		       struct ck_session_info *info));
_CK_DECLARE_FUNCTION (C_GetOperationState,
		      (ck_session_handle_t session,
		       unsigned char *operation_state,
		       unsigned long *operation_state_len));
_CK_DECLARE_FUNCTION (C_SetOperationState,
		      (ck_session_handle_t session,
		       unsigned char *operation_state,
		       unsigned long operation_state_len,
		       ck_object_handle_t encryption_key,
		       ck_object_handle_t authentiation_key));
_CK_DECLARE_FUNCTION (C_Login,
		      (ck_session_handle_t session, ck_user_type_t user_type,
		       unsigned char *pin, unsigned long pin_len));
_CK_DECLARE_FUNCTION (C_Logout, (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_CreateObject,
		      (ck_session_handle_t session,
		       struct ck_attribute *templ,
		       unsigned long count, ck_object_handle_t *object));
_CK_DECLARE_FUNCTION (C_CopyObject,
		      (ck_session_handle_t session, ck_object_handle_t object,
		       struct ck_attribute *templ, unsigned long count,
		       ck_object_handle_t *new_object));
_CK_DECLARE_FUNCTION (C_DestroyObject,
		      (ck_session_handle_t session,
		       ck_object_handle_t object));
_CK_DECLARE_FUNCTION (C_GetObjectSize,
		      (ck_session_handle_t session,
		       ck_object_handle_t object,
		       unsigned long *size));
_CK_DECLARE_FUNCTION (C_GetAttributeValue,
		      (ck_session_handle_t session,
		       ck_object_handle_t object,
		       struct ck_attribute *templ,
		       unsigned long count));
_CK_DECLARE_FUNCTION (C_SetAttributeValue,
		      (ck_session_handle_t session,
		       ck_object_handle_t object,
		       struct ck_attribute *templ,
		       unsigned long count));
_CK_DECLARE_FUNCTION (C_FindObjectsInit,
		      (ck_session_handle_t session,
		       struct ck_attribute *templ,
		       unsigned long count));
_CK_DECLARE_FUNCTION (C_FindObjects,
		      (ck_session_handle_t session,
		       ck_object_handle_t *object,
		       unsigned long max_object_count,
		       unsigned long *object_count));
_CK_DECLARE_FUNCTION (C_FindObjectsFinal,
		      (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_EncryptInit,
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       ck_object_handle_t key));
_CK_DECLARE_FUNCTION (C_Encrypt,
		      (ck_session_handle_t session,
		       unsigned char *data, unsigned long data_len,
		       unsigned char *encrypted_data,
		       unsigned long *encrypted_data_len));
_CK_DECLARE_FUNCTION (C_EncryptUpdate,
		      (ck_session_handle_t session,
		       unsigned char *part, unsigned long part_len,
		       unsigned char *encrypted_part,
		       unsigned long *encrypted_part_len));
_CK_DECLARE_FUNCTION (C_EncryptFinal,
		      (ck_session_handle_t session,
		       unsigned char *last_encrypted_part,
		       unsigned long *last_encrypted_part_len));

_CK_DECLARE_FUNCTION (C_DecryptInit,
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       ck_object_handle_t key));
_CK_DECLARE_FUNCTION (C_Decrypt,
		      (ck_session_handle_t session,
		       unsigned char *encrypted_data,
		       unsigned long encrypted_data_len,
		       unsigned char *data, unsigned long *data_len));
_CK_DECLARE_FUNCTION (C_DecryptUpdate,
		      (ck_session_handle_t session,
		       unsigned char *encrypted_part,
		       unsigned long encrypted_part_len,
		       unsigned char *part, unsigned long *part_len));
_CK_DECLARE_FUNCTION (C_DecryptFinal,
		      (ck_session_handle_t session,
		       unsigned char *last_part,
		       unsigned long *last_part_len));

_CK_DECLARE_FUNCTION (C_DigestInit,
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism));
_CK_DECLARE_FUNCTION (C_Digest,
		      (ck_session_handle_t session,
		       unsigned char *data, unsigned long data_len,
		       unsigned char *digest,
		       unsigned long *digest_len));
_CK_DECLARE_FUNCTION (C_DigestUpdate,
		      (ck_session_handle_t session,
		       unsigned char *part, unsigned long part_len));
_CK_DECLARE_FUNCTION (C_DigestKey,
		      (ck_session_handle_t session, ck_object_handle_t key));
_CK_DECLARE_FUNCTION (C_DigestFinal,
		      (ck_session_handle_t session,
		       unsigned char *digest,
		       unsigned long *digest_len));

_CK_DECLARE_FUNCTION (C_SignInit,
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       ck_object_handle_t key));
_CK_DECLARE_FUNCTION (C_Sign,
		      (ck_session_handle_t session,
		       unsigned char *data, unsigned long data_len,
		       unsigned char *signature,
		       unsigned long *signature_len));
_CK_DECLARE_FUNCTION (C_SignUpdate,
		      (ck_session_handle_t session,
		       unsigned char *part, unsigned long part_len));
_CK_DECLARE_FUNCTION (C_SignFinal,
		      (ck_session_handle_t session,
		       unsigned char *signature,
		       unsigned long *signature_len));
_CK_DECLARE_FUNCTION (C_SignRecoverInit,
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       ck_object_handle_t key));
_CK_DECLARE_FUNCTION (C_SignRecover,
		      (ck_session_handle_t session,
		       unsigned char *data, unsigned long data_len,
		       unsigned char *signature,
		       unsigned long *signature_len));

_CK_DECLARE_FUNCTION (C_VerifyInit,
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       ck_object_handle_t key));
_CK_DECLARE_FUNCTION (C_Verify,
		      (ck_session_handle_t session,
		       unsigned char *data, unsigned long data_len,
		       unsigned char *signature,
		       unsigned long signature_len));
_CK_DECLARE_FUNCTION (C_VerifyUpdate,
		      (ck_session_handle_t session,
		       unsigned char *part, unsigned long part_len));
_CK_DECLARE_FUNCTION (C_VerifyFinal,
		      (ck_session_handle_t session,
		       unsigned char *signature,
		       unsigned long signature_len));
_CK_DECLARE_FUNCTION (C_VerifyRecoverInit,
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       ck_object_handle_t key));
_CK_DECLARE_FUNCTION (C_VerifyRecover,
		      (ck_session_handle_t session,
		       unsigned char *signature,
		       unsigned long signature_len,
		       unsigned char *data,
		       unsigned long *data_len));

_CK_DECLARE_FUNCTION (C_DigestEncryptUpdate,
		      (ck_session_handle_t session,
		       unsigned char *part, unsigned long part_len,
		       unsigned char *encrypted_part,
		       unsigned long *encrypted_part_len));
_CK_DECLARE_FUNCTION (C_DecryptDigestUpdate,
		      (ck_session_handle_t session,
		       unsigned char *encrypted_part,
		       unsigned long encrypted_part_len,
		       unsigned char *part,
		       unsigned long *part_len));
_CK_DECLARE_FUNCTION (C_SignEncryptUpdate,
		      (ck_session_handle_t session,
		       unsigned char *part, unsigned long part_len,
		       unsigned char *encrypted_part,
		       unsigned long *encrypted_part_len));
_CK_DECLARE_FUNCTION (C_DecryptVerifyUpdate,
		      (ck_session_handle_t session,
		       unsigned char *encrypted_part,
		       unsigned long encrypted_part_len,
		       unsigned char *part,
		       unsigned long *part_len));

_CK_DECLARE_FUNCTION (C_GenerateKey,
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       struct ck_attribute *templ,
		       unsigned long count,
		       ck_object_handle_t *key));
_CK_DECLARE_FUNCTION (C_GenerateKeyPair,
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       struct ck_attribute *public_key_template,
		       unsigned long public_key_attribute_count,
		       struct ck_attribute *private_key_template,
		       unsigned long private_key_attribute_count,
		       ck_object_handle_t *public_key,
		       ck_object_handle_t *private_key));
_CK_DECLARE_FUNCTION (C_WrapKey,
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       ck_object_handle_t wrapping_key,
		       ck_object_handle_t key,
		       unsigned char *wrapped_key,
		       unsigned long *wrapped_key_len));
_CK_DECLARE_FUNCTION (C_UnwrapKey,
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       ck_object_handle_t unwrapping_key,
		       unsigned char *wrapped_key,
		       unsigned long wrapped_key_len,
		       struct ck_attribute *templ,
		       unsigned long attribute_count,
		       ck_object_handle_t *key));
_CK_DECLARE_FUNCTION (C_DeriveKey,
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       ck_object_handle_t base_key,
		       struct ck_attribute *templ,
		       unsigned long attribute_count,
		       ck_object_handle_t *key));

_CK_DECLARE_FUNCTION (C_SeedRandom,
		      (ck_session_handle_t session, unsigned char *seed,
		       unsigned long seed_len));
_CK_DECLARE_FUNCTION (C_GenerateRandom,
		      (ck_session_handle_t session,
		       unsigned char *random_data,
		       unsigned long random_len));

_CK_DECLARE_FUNCTION (C_GetFunctionStatus, (ck_session_handle_t session));
_CK_DECLARE_FUNCTION (C_CancelFunction, (ck_session_handle_t session));

"""

# ck_rv_t CK_C_Initialize (void *init_args)
CK_C_Initialize  = CFUNCTYPE(ck_rv_t, c_void_p)
# ck_rv_t CK_C_Finalize (void *reserved)
CK_C_Finalize  = CFUNCTYPE(ck_rv_t, c_void_p)
# ck_rv_t CK_C_GetInfo (struct ck_info *info)
CK_C_GetInfo  = CFUNCTYPE(ck_rv_t, POINTER(ck_info))
# ck_rv_t CK_C_GetFunctionList (struct ck_function_list **function_list)
CK_C_GetFunctionList  = CFUNCTYPE(ck_rv_t, c_void_p)
# ck_rv_t CK_C_GetSlotList (unsigned char token_present, ck_slot_id_t *slot_list, unsigned long *count)
CK_C_GetSlotList  = CFUNCTYPE(ck_rv_t, c_ubyte, c_void_p, POINTER(c_ulong))
# ck_rv_t CK_C_GetSlotInfo (ck_slot_id_t slot_id, struct ck_slot_info *info)
CK_C_GetSlotInfo  = CFUNCTYPE(ck_rv_t, ck_slot_id_t, POINTER(ck_slot_info))
# ck_rv_t CK_C_GetTokenInfo (ck_slot_id_t slot_id, struct ck_token_info *info)
CK_C_GetTokenInfo  = CFUNCTYPE(ck_rv_t, ck_slot_id_t, POINTER(ck_token_info))
# ck_rv_t CK_C_WaitForSlotEvent (ck_flags_t flags, ck_slot_id_t *slot, void *reserved)
CK_C_WaitForSlotEvent  = CFUNCTYPE(ck_rv_t, ck_flags_t, POINTER(ck_slot_id_t), c_void_p)
# ck_rv_t CK_C_GetMechanismList (ck_slot_id_t slot_id, ck_mechanism_type_t *mechanism_list, unsigned long *count)
CK_C_GetMechanismList  = CFUNCTYPE(ck_rv_t, ck_slot_id_t, c_void_p, POINTER(c_ulong))
# ck_rv_t CK_C_GetMechanismInfo (ck_slot_id_t slot_id, ck_mechanism_type_t type, struct ck_mechanism_info *info)
CK_C_GetMechanismInfo  = CFUNCTYPE(ck_rv_t, ck_slot_id_t, ck_mechanism_type_t, POINTER(ck_mechanism_info))
# ck_rv_t CK_C_InitToken (ck_slot_id_t slot_id, unsigned char *pin, unsigned long pin_len, unsigned char *label)
CK_C_InitToken  = CFUNCTYPE(ck_rv_t, ck_slot_id_t, c_void_p, c_ulong, c_void_p)
# ck_rv_t CK_C_InitPIN (ck_session_handle_t session, unsigned char *pin, unsigned long pin_len)
CK_C_InitPIN  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, c_void_p, c_ulong)
# ck_rv_t CK_C_SetPIN (ck_session_handle_t session, unsigned char *old_pin, unsigned long old_len, unsigned char *new_pin, unsigned long new_len)
CK_C_SetPIN  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, c_void_p, c_ulong, c_void_p, c_ulong)
# ck_rv_t CK_C_OpenSession (ck_slot_id_t slot_id, ck_flags_t flags, void *application, ck_notify_t notify, ck_session_handle_t *session)
CK_C_OpenSession  = CFUNCTYPE(ck_rv_t, ck_slot_id_t, ck_flags_t, c_void_p, ck_notify_t, POINTER(ck_session_handle_t))
# ck_rv_t CK_C_CloseSession (ck_session_handle_t session)
CK_C_CloseSession  = CFUNCTYPE(ck_rv_t, ck_session_handle_t)
# ck_rv_t CK_C_CloseAllSessions (ck_slot_id_t slot_id)
CK_C_CloseAllSessions  = CFUNCTYPE(ck_rv_t, ck_slot_id_t)
# ck_rv_t CK_C_GetSessionInfo (ck_session_handle_t session, struct ck_session_info *info)
CK_C_GetSessionInfo  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, POINTER(ck_session_info))
# ck_rv_t CK_C_GetOperationState (ck_session_handle_t session, unsigned char *operation_state, unsigned long *operation_state_len)
CK_C_GetOperationState  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, c_void_p, POINTER(c_ulong))
# ck_rv_t CK_C_SetOperationState (ck_session_handle_t session, unsigned char *operation_state, unsigned long operation_state_len, ck_object_handle_t encryption_key, ck_object_handle_t authentiation_key)
CK_C_SetOperationState  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, c_void_p, c_ulong, ck_object_handle_t, ck_object_handle_t)
# ck_rv_t CK_C_Login (ck_session_handle_t session, ck_user_type_t user_type, unsigned char *pin, unsigned long pin_len)
CK_C_Login  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, ck_user_type_t, c_void_p, c_ulong)
# ck_rv_t CK_C_Logout (ck_session_handle_t session)
CK_C_Logout  = CFUNCTYPE(ck_rv_t, ck_session_handle_t)
# ck_rv_t CK_C_CreateObject (ck_session_handle_t session, struct ck_attribute *templ, unsigned long count, ck_object_handle_t *object)
CK_C_CreateObject  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, POINTER(ck_attribute), c_ulong, POINTER(ck_object_handle_t))
# ck_rv_t CK_C_CopyObject (ck_session_handle_t session, ck_object_handle_t object, struct ck_attribute *templ, unsigned long count, ck_object_handle_t *new_object)
CK_C_CopyObject  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, ck_object_handle_t, POINTER(ck_attribute), c_ulong, POINTER(ck_object_handle_t))
# ck_rv_t CK_C_DestroyObject (ck_session_handle_t session, ck_object_handle_t object)
CK_C_DestroyObject  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, ck_object_handle_t)
# ck_rv_t CK_C_GetObjectSize (ck_session_handle_t session, ck_object_handle_t object, unsigned long *size)
CK_C_GetObjectSize  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, ck_object_handle_t, POINTER(c_ulong))
# ck_rv_t CK_C_GetAttributeValue (ck_session_handle_t session, ck_object_handle_t object, struct ck_attribute *templ, unsigned long count)
CK_C_GetAttributeValue  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, ck_object_handle_t, POINTER(ck_attribute), c_ulong)
# ck_rv_t CK_C_SetAttributeValue (ck_session_handle_t session, ck_object_handle_t object, struct ck_attribute *templ, unsigned long count)
CK_C_SetAttributeValue  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, ck_object_handle_t, POINTER(ck_attribute), c_ulong)
# ck_rv_t CK_C_FindObjectsInit (ck_session_handle_t session, struct ck_attribute *templ, unsigned long count)
CK_C_FindObjectsInit  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, POINTER(ck_attribute), c_ulong)
# ck_rv_t CK_C_FindObjects (ck_session_handle_t session, ck_object_handle_t *object, unsigned long max_object_count, unsigned long *object_count)
CK_C_FindObjects  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, c_void_p, c_ulong, POINTER(c_ulong))
# ck_rv_t CK_C_FindObjectsFinal (ck_session_handle_t session)
CK_C_FindObjectsFinal  = CFUNCTYPE(ck_rv_t, ck_session_handle_t)
# ck_rv_t CK_C_EncryptInit (ck_session_handle_t session, struct ck_mechanism *mechanism, ck_object_handle_t key)
CK_C_EncryptInit  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, POINTER(ck_mechanism), ck_object_handle_t)
# ck_rv_t CK_C_Encrypt (ck_session_handle_t session, unsigned char *data, unsigned long data_len, unsigned char *encrypted_data, unsigned long *encrypted_data_len)
CK_C_Encrypt  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, c_void_p, c_ulong, c_void_p, POINTER(c_ulong))
# ck_rv_t CK_C_EncryptUpdate (ck_session_handle_t session, unsigned char *part, unsigned long part_len, unsigned char *encrypted_part, unsigned long *encrypted_part_len)
CK_C_EncryptUpdate  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, c_void_p, c_ulong, c_void_p, POINTER(c_ulong))
# ck_rv_t CK_C_EncryptFinal (ck_session_handle_t session, unsigned char *last_encrypted_part, unsigned long *last_encrypted_part_len)
CK_C_EncryptFinal  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, c_void_p, POINTER(c_ulong))
# ck_rv_t CK_C_DecryptInit (ck_session_handle_t session, struct ck_mechanism *mechanism, ck_object_handle_t key)
CK_C_DecryptInit  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, POINTER(ck_mechanism), ck_object_handle_t)
# ck_rv_t CK_C_Decrypt (ck_session_handle_t session, unsigned char *encrypted_data, unsigned long encrypted_data_len, unsigned char *data, unsigned long *data_len)
CK_C_Decrypt  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, c_void_p, c_ulong, c_void_p, POINTER(c_ulong))
# ck_rv_t CK_C_DecryptUpdate (ck_session_handle_t session, unsigned char *encrypted_part, unsigned long encrypted_part_len, unsigned char *part, unsigned long *part_len)
CK_C_DecryptUpdate  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, c_void_p, c_ulong, c_void_p, POINTER(c_ulong))
# ck_rv_t CK_C_DecryptFinal (ck_session_handle_t session, unsigned char *last_part, unsigned long *last_part_len)
CK_C_DecryptFinal  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, c_void_p, POINTER(c_ulong))
# ck_rv_t CK_C_DigestInit (ck_session_handle_t session, struct ck_mechanism *mechanism)
CK_C_DigestInit  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, POINTER(ck_mechanism))
# ck_rv_t CK_C_Digest (ck_session_handle_t session, unsigned char *data, unsigned long data_len, unsigned char *digest, unsigned long *digest_len)
CK_C_Digest  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, c_void_p, c_ulong, c_void_p, POINTER(c_ulong))
# ck_rv_t CK_C_DigestUpdate (ck_session_handle_t session, unsigned char *part, unsigned long part_len)
CK_C_DigestUpdate  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, c_void_p, c_ulong)
# ck_rv_t CK_C_DigestKey (ck_session_handle_t session, ck_object_handle_t key)
CK_C_DigestKey  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, ck_object_handle_t)
# ck_rv_t CK_C_DigestFinal (ck_session_handle_t session, unsigned char *digest, unsigned long *digest_len)
CK_C_DigestFinal  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, c_void_p, POINTER(c_ulong))
# ck_rv_t CK_C_SignInit (ck_session_handle_t session, struct ck_mechanism *mechanism, ck_object_handle_t key)
CK_C_SignInit  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, POINTER(ck_mechanism), ck_object_handle_t)
# ck_rv_t CK_C_Sign (ck_session_handle_t session, unsigned char *data, unsigned long data_len, unsigned char *signature, unsigned long *signature_len)
CK_C_Sign  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, c_void_p, c_ulong, c_void_p, POINTER(c_ulong))
# ck_rv_t CK_C_SignUpdate (ck_session_handle_t session, unsigned char *part, unsigned long part_len)
CK_C_SignUpdate  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, c_void_p, c_ulong)
# ck_rv_t CK_C_SignFinal (ck_session_handle_t session, unsigned char *signature, unsigned long *signature_len)
CK_C_SignFinal  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, c_void_p, POINTER(c_ulong))
# ck_rv_t CK_C_SignRecoverInit (ck_session_handle_t session, struct ck_mechanism *mechanism, ck_object_handle_t key)
CK_C_SignRecoverInit  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, POINTER(ck_mechanism), ck_object_handle_t)
# ck_rv_t CK_C_SignRecover (ck_session_handle_t session, unsigned char *data, unsigned long data_len, unsigned char *signature, unsigned long *signature_len)
CK_C_SignRecover  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, c_void_p, c_ulong, c_void_p, POINTER(c_ulong))
# ck_rv_t CK_C_VerifyInit (ck_session_handle_t session, struct ck_mechanism *mechanism, ck_object_handle_t key)
CK_C_VerifyInit  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, POINTER(ck_mechanism), ck_object_handle_t)
# ck_rv_t CK_C_Verify (ck_session_handle_t session, unsigned char *data, unsigned long data_len, unsigned char *signature, unsigned long signature_len)
CK_C_Verify  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, c_void_p, c_ulong, c_void_p, c_ulong)
# ck_rv_t CK_C_VerifyUpdate (ck_session_handle_t session, unsigned char *part, unsigned long part_len)
CK_C_VerifyUpdate  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, c_void_p, c_ulong)
# ck_rv_t CK_C_VerifyFinal (ck_session_handle_t session, unsigned char *signature, unsigned long signature_len)
CK_C_VerifyFinal  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, c_void_p, c_ulong)
# ck_rv_t CK_C_VerifyRecoverInit (ck_session_handle_t session, struct ck_mechanism *mechanism, ck_object_handle_t key)
CK_C_VerifyRecoverInit  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, POINTER(ck_mechanism), ck_object_handle_t)
# ck_rv_t CK_C_VerifyRecover (ck_session_handle_t session, unsigned char *signature, unsigned long signature_len, unsigned char *data, unsigned long *data_len)
CK_C_VerifyRecover  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, c_void_p, c_ulong, c_void_p, POINTER(c_ulong))
# ck_rv_t CK_C_DigestEncryptUpdate (ck_session_handle_t session, unsigned char *part, unsigned long part_len, unsigned char *encrypted_part, unsigned long *encrypted_part_len)
CK_C_DigestEncryptUpdate  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, c_void_p, c_ulong, c_void_p, POINTER(c_ulong))
# ck_rv_t CK_C_DecryptDigestUpdate (ck_session_handle_t session, unsigned char *encrypted_part, unsigned long encrypted_part_len, unsigned char *part, unsigned long *part_len)
CK_C_DecryptDigestUpdate  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, c_void_p, c_ulong, c_void_p, POINTER(c_ulong))
# ck_rv_t CK_C_SignEncryptUpdate (ck_session_handle_t session, unsigned char *part, unsigned long part_len, unsigned char *encrypted_part, unsigned long *encrypted_part_len)
CK_C_SignEncryptUpdate  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, c_void_p, c_ulong, c_void_p, POINTER(c_ulong))
# ck_rv_t CK_C_DecryptVerifyUpdate (ck_session_handle_t session, unsigned char *encrypted_part, unsigned long encrypted_part_len, unsigned char *part, unsigned long *part_len)
CK_C_DecryptVerifyUpdate  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, c_void_p, c_ulong, c_void_p, POINTER(c_ulong))
# ck_rv_t CK_C_GenerateKey (ck_session_handle_t session, struct ck_mechanism *mechanism, struct ck_attribute *templ, unsigned long count, ck_object_handle_t *key)
CK_C_GenerateKey  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, POINTER(ck_mechanism), c_void_p, c_ulong, POINTER(ck_object_handle_t))
# ck_rv_t CK_C_GenerateKeyPair (ck_session_handle_t session, struct ck_mechanism *mechanism, struct ck_attribute *public_key_template, unsigned long public_key_attribute_count, struct ck_attribute *private_key_template, unsigned long private_key_attribute_count, ck_object_handle_t *public_key, ck_object_handle_t *private_key)
CK_C_GenerateKeyPair  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, POINTER(ck_mechanism), c_void_p, c_ulong, POINTER(ck_attribute), c_ulong, POINTER(ck_object_handle_t), POINTER(ck_object_handle_t))
# ck_rv_t CK_C_WrapKey (ck_session_handle_t session, struct ck_mechanism *mechanism, ck_object_handle_t wrapping_key, ck_object_handle_t key, unsigned char *wrapped_key, unsigned long *wrapped_key_len)
CK_C_WrapKey  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, POINTER(ck_mechanism), ck_object_handle_t, ck_object_handle_t, c_void_p, POINTER(c_ulong))
# ck_rv_t CK_C_UnwrapKey (ck_session_handle_t session, struct ck_mechanism *mechanism, ck_object_handle_t unwrapping_key, unsigned char *wrapped_key, unsigned long wrapped_key_len, struct ck_attribute *templ, unsigned long attribute_count, ck_object_handle_t *key)
CK_C_UnwrapKey  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, POINTER(ck_mechanism), ck_object_handle_t, c_void_p, c_ulong, c_void_p, c_ulong, POINTER(ck_object_handle_t))
# ck_rv_t CK_C_DeriveKey (ck_session_handle_t session, struct ck_mechanism *mechanism, ck_object_handle_t base_key, struct ck_attribute *templ, unsigned long attribute_count, ck_object_handle_t *key)
CK_C_DeriveKey  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, POINTER(ck_mechanism), ck_object_handle_t, c_void_p, c_ulong, POINTER(ck_object_handle_t))
# ck_rv_t CK_C_SeedRandom (ck_session_handle_t session, unsigned char *seed, unsigned long seed_len)
CK_C_SeedRandom  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, c_void_p, c_ulong)
# ck_rv_t CK_C_GenerateRandom (ck_session_handle_t session, unsigned char *random_data, unsigned long random_len)
CK_C_GenerateRandom  = CFUNCTYPE(ck_rv_t, ck_session_handle_t, c_void_p, c_ulong)
# ck_rv_t CK_C_GetFunctionStatus (ck_session_handle_t session)
CK_C_GetFunctionStatus  = CFUNCTYPE(ck_rv_t, ck_session_handle_t)
# ck_rv_t CK_C_CancelFunction (ck_session_handle_t session)
CK_C_CancelFunction  = CFUNCTYPE(ck_rv_t, ck_session_handle_t)

class ck_function_list(Structure):
    _fields_ = [
        ("version", ck_version),
        ("C_Initialize", CK_C_Initialize),
        ("C_Finalize", CK_C_Finalize),
        ("C_GetInfo", CK_C_GetInfo),
        ("C_GetFunctionList", CK_C_GetFunctionList),
        ("C_GetSlotList", CK_C_GetSlotList),
        ("C_GetSlotInfo", CK_C_GetSlotInfo),
        ("C_GetTokenInfo", CK_C_GetTokenInfo),
        ("C_GetMechanismList", CK_C_GetMechanismList),
        ("C_GetMechanismInfo", CK_C_GetMechanismInfo),
        ("C_InitToken", CK_C_InitToken),
        ("C_InitPIN", CK_C_InitPIN),
        ("C_SetPIN", CK_C_SetPIN),
        ("C_OpenSession", CK_C_OpenSession),
        ("C_CloseSession", CK_C_CloseSession),
        ("C_CloseAllSessions", CK_C_CloseAllSessions),
        ("C_GetSessionInfo", CK_C_GetSessionInfo),
        ("C_GetOperationState", CK_C_GetOperationState),
        ("C_SetOperationState", CK_C_SetOperationState),
        ("C_Login", CK_C_Login),
        ("C_Logout", CK_C_Logout),
        ("C_CreateObject", CK_C_CreateObject),
        ("C_CopyObject", CK_C_CopyObject),
        ("C_DestroyObject", CK_C_DestroyObject),
        ("C_GetObjectSize", CK_C_GetObjectSize),
        ("C_GetAttributeValue", CK_C_GetAttributeValue),
        ("C_SetAttributeValue", CK_C_SetAttributeValue),
        ("C_FindObjectsInit", CK_C_FindObjectsInit),
        ("C_FindObjects", CK_C_FindObjects),
        ("C_FindObjectsFinal", CK_C_FindObjectsFinal),
        ("C_EncryptInit", CK_C_EncryptInit),
        ("C_Encrypt", CK_C_Encrypt),
        ("C_EncryptUpdate", CK_C_EncryptUpdate),
        ("C_EncryptFinal", CK_C_EncryptFinal),
        ("C_DecryptInit", CK_C_DecryptInit),
        ("C_Decrypt", CK_C_Decrypt),
        ("C_DecryptUpdate", CK_C_DecryptUpdate),
        ("C_DecryptFinal", CK_C_DecryptFinal),
        ("C_DigestInit", CK_C_DigestInit),
        ("C_Digest", CK_C_Digest),
        ("C_DigestUpdate", CK_C_DigestUpdate),
        ("C_DigestKey", CK_C_DigestKey),
        ("C_DigestFinal", CK_C_DigestFinal),
        ("C_SignInit", CK_C_SignInit),
        ("C_Sign", CK_C_Sign),
        ("C_SignUpdate", CK_C_SignUpdate),
        ("C_SignFinal", CK_C_SignFinal),
        ("C_SignRecoverInit", CK_C_SignRecoverInit),
        ("C_SignRecover", CK_C_SignRecover),
        ("C_VerifyInit", CK_C_VerifyInit),
        ("C_Verify", CK_C_Verify),
        ("C_VerifyUpdate", CK_C_VerifyUpdate),
        ("C_VerifyFinal", CK_C_VerifyFinal),
        ("C_VerifyRecoverInit", CK_C_VerifyRecoverInit),
        ("C_VerifyRecover", CK_C_VerifyRecover),
        ("C_DigestEncryptUpdate", CK_C_DigestEncryptUpdate),
        ("C_DecryptDigestUpdate", CK_C_DecryptDigestUpdate),
        ("C_SignEncryptUpdate", CK_C_SignEncryptUpdate),
        ("C_DecryptVerifyUpdate", CK_C_DecryptVerifyUpdate),
        ("C_GenerateKey", CK_C_GenerateKey),
        ("C_GenerateKeyPair", CK_C_GenerateKeyPair),
        ("C_WrapKey", CK_C_WrapKey),
        ("C_UnwrapKey", CK_C_UnwrapKey),
        ("C_DeriveKey", CK_C_DeriveKey),
        ("C_SeedRandom", CK_C_SeedRandom),
        ("C_GenerateRandom", CK_C_GenerateRandom),
        ("C_GetFunctionStatus", CK_C_GetFunctionStatus),
        ("C_CancelFunction", CK_C_CancelFunction),
        ("C_WaitForSlotEvent", CK_C_WaitForSlotEvent),
    ]


aliases["ck_function_list"] = ck_function_list
"""
typedef ck_rv_t (*ck_createmutex_t) (void **mutex);
typedef ck_rv_t (*ck_destroymutex_t) (void *mutex);
typedef ck_rv_t (*ck_lockmutex_t) (void *mutex);
typedef ck_rv_t (*ck_unlockmutex_t) (void *mutex);


struct ck_c_initialize_args
{
  ck_createmutex_t create_mutex;
  ck_destroymutex_t destroy_mutex;
  ck_lockmutex_t lock_mutex;
  ck_unlockmutex_t unlock_mutex;
  ck_flags_t flags;
  void *reserved;
};
"""

CKF_LIBRARY_CANT_CREATE_OS_THREADS = 1 << 0
CKF_OS_LOCKING_OK = 1 << 1

CKR_OK = 0
CKR_CANCEL = 1
CKR_HOST_MEMORY = 2
CKR_SLOT_ID_INVALID = 3
CKR_GENERAL_ERROR = 5
CKR_FUNCTION_FAILED = 6
CKR_ARGUMENTS_BAD = 7
CKR_NO_EVENT = 8
CKR_NEED_TO_CREATE_THREADS = 9
CKR_CANT_LOCK = 0xA
CKR_ATTRIBUTE_READ_ONLY = 0x10
CKR_ATTRIBUTE_SENSITIVE = 0x11
CKR_ATTRIBUTE_TYPE_INVALID = 0x12
CKR_ATTRIBUTE_VALUE_INVALID = 0x13
CKR_DATA_INVALID = 0x20
CKR_DATA_LEN_RANGE = 0x21
CKR_DEVICE_ERROR = 0x30
CKR_DEVICE_MEMORY = 0x31
CKR_DEVICE_REMOVED = 0x32
CKR_ENCRYPTED_DATA_INVALID = 0x40
CKR_ENCRYPTED_DATA_LEN_RANGE = 0x41
CKR_FUNCTION_CANCELED = 0x50
CKR_FUNCTION_NOT_PARALLEL = 0x51
CKR_FUNCTION_NOT_SUPPORTED = 0x54
CKR_KEY_HANDLE_INVALID = 0x60
CKR_KEY_SIZE_RANGE = 0x62
CKR_KEY_TYPE_INCONSISTENT = 0x63
CKR_KEY_NOT_NEEDED = 0x64
CKR_KEY_CHANGED = 0x65
CKR_KEY_NEEDED = 0x66
CKR_KEY_INDIGESTIBLE = 0x67
CKR_KEY_FUNCTION_NOT_PERMITTED = 0x68
CKR_KEY_NOT_WRAPPABLE = 0x69
CKR_KEY_UNEXTRACTABLE = 0x6A
CKR_MECHANISM_INVALID = 0x70
CKR_MECHANISM_PARAM_INVALID = 0x71
CKR_OBJECT_HANDLE_INVALID = 0x82
CKR_OPERATION_ACTIVE = 0x90
CKR_OPERATION_NOT_INITIALIZED = 0x91
CKR_PIN_INCORRECT = 0xA0
CKR_PIN_INVALID = 0xA1
CKR_PIN_LEN_RANGE = 0xA2
CKR_PIN_EXPIRED = 0xA3
CKR_PIN_LOCKED = 0xA4
CKR_SESSION_CLOSED = 0xB0
CKR_SESSION_COUNT = 0xB1
CKR_SESSION_HANDLE_INVALID = 0xB3
CKR_SESSION_PARALLEL_NOT_SUPPORTED = 0xB4
CKR_SESSION_READ_ONLY = 0xB5
CKR_SESSION_EXISTS = 0xB6
CKR_SESSION_READ_ONLY_EXISTS = 0xB7
CKR_SESSION_READ_WRITE_SO_EXISTS = 0xB8
CKR_SIGNATURE_INVALID = 0xC0
CKR_SIGNATURE_LEN_RANGE = 0xC1
CKR_TEMPLATE_INCOMPLETE = 0xD0
CKR_TEMPLATE_INCONSISTENT = 0xD1
CKR_TOKEN_NOT_PRESENT = 0xE0
CKR_TOKEN_NOT_RECOGNIZED = 0xE1
CKR_TOKEN_WRITE_PROTECTED = 0xE2
CKR_UNWRAPPING_KEY_HANDLE_INVALID = 0xF0
CKR_UNWRAPPING_KEY_SIZE_RANGE = 0xF1
CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT = 0xF2
CKR_USER_ALREADY_LOGGED_IN = 0x100
CKR_USER_NOT_LOGGED_IN = 0x101
CKR_USER_PIN_NOT_INITIALIZED = 0x102
CKR_USER_TYPE_INVALID = 0x103
CKR_USER_ANOTHER_ALREADY_LOGGED_IN = 0x104
CKR_USER_TOO_MANY_TYPES = 0x105
CKR_WRAPPED_KEY_INVALID = 0x110
CKR_WRAPPED_KEY_LEN_RANGE = 0x112
CKR_WRAPPING_KEY_HANDLE_INVALID = 0x113
CKR_WRAPPING_KEY_SIZE_RANGE = 0x114
CKR_WRAPPING_KEY_TYPE_INCONSISTENT = 0x115
CKR_RANDOM_SEED_NOT_SUPPORTED = 0x120
CKR_RANDOM_NO_RNG = 0x121
CKR_DOMAIN_PARAMS_INVALID = 0x130
CKR_BUFFER_TOO_SMALL = 0x150
CKR_SAVED_STATE_INVALID = 0x160
CKR_INFORMATION_SENSITIVE = 0x170
CKR_STATE_UNSAVEABLE = 0x180
CKR_CRYPTOKI_NOT_INITIALIZED = 0x190
CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x191
CKR_MUTEX_BAD = 0x1A0
CKR_MUTEX_NOT_LOCKED = 0x1A1
CKR_FUNCTION_REJECTED = 0x200
CKR_VENDOR_DEFINED = 1 << 31

CK_FALSE = 0
CK_TRUE = 1

'''
ctypedef("typedef unsigned char CK_BYTE;")
ctypedef("typedef unsigned char CK_CHAR;")
ctypedef("typedef unsigned char CK_UTF8CHAR;")
ctypedef("typedef unsigned char CK_BBOOL;")
ctypedef("typedef unsigned long int CK_ULONG;")
ctypedef("typedef long int CK_LONG;")
ctypedef("typedef CK_BYTE *CK_BYTE_PTR;")
ctypedef("typedef CK_CHAR *CK_CHAR_PTR;")
ctypedef("typedef CK_UTF8CHAR *CK_UTF8CHAR_PTR;")
ctypedef("typedef CK_ULONG *CK_ULONG_PTR;")
ctypedef("typedef void *CK_VOID_PTR;")
ctypedef("typedef void **CK_VOID_PTR_PTR;")
# define CK_FALSE 0
# define CK_TRUE 1

ctypedef("typedef struct ck_version CK_VERSION;")
ctypedef("typedef struct ck_version *CK_VERSION_PTR;")

ctypedef("typedef struct ck_info CK_INFO;")
ctypedef("typedef struct ck_info *CK_INFO_PTR;")

ctypedef("typedef ck_slot_id_t *CK_SLOT_ID_PTR;")

ctypedef("typedef struct ck_slot_info CK_SLOT_INFO;")
ctypedef("typedef struct ck_slot_info *CK_SLOT_INFO_PTR;")

ctypedef("typedef struct ck_token_info CK_TOKEN_INFO;")
ctypedef("typedef struct ck_token_info *CK_TOKEN_INFO_PTR;")

ctypedef("typedef ck_session_handle_t *CK_SESSION_HANDLE_PTR;")

ctypedef("typedef struct ck_session_info CK_SESSION_INFO;")
ctypedef("typedef struct ck_session_info *CK_SESSION_INFO_PTR;")

ctypedef("typedef ck_object_handle_t *CK_OBJECT_HANDLE_PTR;")

ctypedef("typedef ck_object_class_t *CK_OBJECT_CLASS_PTR;")

ctypedef("typedef struct ck_attribute CK_ATTRIBUTE;")
ctypedef("typedef struct ck_attribute *CK_ATTRIBUTE_PTR;")

ctypedef("typedef struct ck_date CK_DATE;")
ctypedef("typedef struct ck_date *CK_DATE_PTR;")

ctypedef("typedef ck_mechanism_type_t *CK_MECHANISM_TYPE_PTR;")

ctypedef("typedef struct ck_mechanism CK_MECHANISM;")
ctypedef("typedef struct ck_mechanism *CK_MECHANISM_PTR;")

ctypedef("typedef struct ck_mechanism_info CK_MECHANISM_INFO;")
ctypedef("typedef struct ck_mechanism_info *CK_MECHANISM_INFO_PTR;")

ctypedef("typedef struct ck_rsa_pkcs_oaep_params CK_RSA_PKCS_OAEP_PARAMS;")
ctypedef("typedef struct ck_rsa_pkcs_oaep_params *CK_RSA_PKCS_OAEP_PARAMS_PTR;")

ctypedef("typedef struct ck_rsa_pkcs_pss_params CK_RSA_PKCS_PSS_PARAMS;")
ctypedef("typedef struct ck_rsa_pkcs_pss_params *CK_RSA_PKCS_PSS_PARAMS_PTR;")

ctypedef("typedef struct ck_gcm_params CK_GCM_PARAMS;")

ctypedef("typedef struct ck_function_list CK_FUNCTION_LIST;")
ctypedef("typedef struct ck_function_list *CK_FUNCTION_LIST_PTR;")
ctypedef("typedef struct ck_function_list **CK_FUNCTION_LIST_PTR_PTR;")

ctypedef("typedef struct ck_c_initialize_args CK_C_INITIALIZE_ARGS;")
ctypedef("typedef struct ck_c_initialize_args *CK_C_INITIALIZE_ARGS_PTR;")

# define NULL_PTR NULL

""" Delete the helper macros defined at the top of the file.  """
# undef ck_flags_t
# undef ck_version

# undef ck_info
# undef cryptoki_version
# undef manufacturer_id
# undef library_description
# undef library_version

# undef ck_notification_t
# undef ck_slot_id_t

# undef ck_slot_info
# undef slot_description
# undef hardware_version
# undef firmware_version

# undef ck_token_info
# undef serial_number
# undef max_session_count
# undef session_count
# undef max_rw_session_count
# undef rw_session_count
# undef max_pin_len
# undef min_pin_len
# undef total_public_memory
# undef free_public_memory
# undef total_private_memory
# undef free_private_memory
# undef utc_time

# undef ck_session_handle_t
# undef ck_user_type_t
# undef ck_state_t

# undef ck_session_info
# undef slot_id
# undef device_error

# undef ck_object_handle_t
# undef ck_object_class_t
# undef ck_hw_feature_type_t
# undef ck_key_type_t
# undef ck_certificate_type_t
# undef ck_attribute_type_t

# undef ck_attribute
# undef value
# undef value_len

# undef ck_date

# undef ck_mechanism_type_t

# undef ck_mechanism
# undef parameter
# undef parameter_len

# undef ck_mechanism_info
# undef min_key_size
# undef max_key_size

# undef ck_rsa_pkcs_oaep_params

# undef ck_rsa_pkcs_pss_params

# undef ck_rsa_pkcs_pss_params

# undef ck_rv_t
# undef ck_notify_t

# undef ck_function_list

# undef ck_createmutex_t
# undef ck_destroymutex_t
# undef ck_lockmutex_t
# undef ck_unlockmutex_t

# undef ck_c_initialize_args
# undef create_mutex
# undef destroy_mutex
# undef lock_mutex
# undef unlock_mutex
# undef reserved
'''
# endif	''' CRYPTOKI_COMPAT '''


""" System dependencies.  """
# if defined(_WIN32) || defined(CRYPTOKI_FORCE_WIN32)
# pragma pack(pop, cryptoki)
# endif

# if defined(__cplusplus)
# }
# endif

# endif	''' PKCS11_H '''

CKA_GOSTR3410_PARAMS = 0x00000250
CKA_GOSTR3411_PARAMS = 0x00000251

CKD_NULL = 0x00000001

CKK_GOSTR3410 =0x00000030
CKK_GOSTR3411 = 0x00000031

CKM_AES_GCM = 0x00001087
CKM_GOSTR3410 = 0x00001201
CKM_GOSTR3410_DERIVE = 0x00001204
CKM_GOSTR3410_KEY_PAIR_GEN = 0x00001200
CKM_GOSTR3410_KEY_WRAP = 0x00001203
CKM_GOSTR3410_WITH_GOSTR3411 = 0x00001202
CKM_GOSTR3411 = 0x00001210
CKM_GOSTR3411_HMAC = 0x00001211

CKP_PKCS5_PBKD2_HMAC_GOSTR3411 = 0x00000002

CKZ_DATA_SPECIFIED = 0x00000001
CKZ_SALT_SPECIFIED = 0x00000001

AttrIsBool = (
    CKA_ALWAYS_AUTHENTICATE,
    CKA_ALWAYS_SENSITIVE,
    CKA_DECRYPT,
    CKA_DERIVE,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_HAS_RESET,
    CKA_LOCAL,
    CKA_MODIFIABLE,
    CKA_NEVER_EXTRACTABLE,
    CKA_PRIVATE,
    CKA_RESET_ON_INIT,
    CKA_SECONDARY_AUTH,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_SIGN_RECOVER,
    CKA_TOKEN,
    CKA_TRUSTED,
    CKA_UNWRAP,
    CKA_VERIFY,
    CKA_VERIFY_RECOVER,
    CKA_WRAP,
    CKA_WRAP_WITH_TRUSTED
)
AttrIsNum= (
    CKA_CERTIFICATE_TYPE,
    CKA_CLASS,
    CKA_HW_FEATURE_TYPE,
    CKA_KEY_GEN_MECHANISM,
    CKA_KEY_TYPE,
    CKA_MODULUS_BITS,
    CKA_VALUE_BITS,
    CKA_VALUE_LEN
)

AttrIsString = (
    CKA_LABEL,
    CKA_APPLICATION
)

AttrIsList = (
    CKA_WRAP_TEMPLATE,
    CKA_UNWRAP_TEMPLATE
)
def AttrIsBin(type):
    return (
        type not in AttrIsBool
        and type not in AttrIsString
        and type not in AttrIsNum
    )

def fillDict(prefix):
    d = {}
    lp = len(prefix)
    kv = globals()
    for k in kv:
        v = kv[k]
        if k[:lp] == prefix:
            d[v] = k
            d[k] = v
    return d

CKA = fillDict('CKA_')
CKC = fillDict('CKC_')
CKD = fillDict('CKD_')
CKF = fillDict('CKF_')
CKG = fillDict('CKG_')
CKH = fillDict('CKH_')
CKK = fillDict('CKK_')
CKM = fillDict('CKM_')
CKO = fillDict('CKO_')
CKR = fillDict('CKR_')
CKS = fillDict('CKS_')
CKU = fillDict('CKU_')
CKZ = fillDict('CKZ_')

def buffer(data):
    if type(data) == int:
        bdata = create_string_buffer(data)
    else:
        bdata = create_string_buffer(len(data))
        bdata.value = data
    return bdata

Mechanism = ck_mechanism

MechanismSHA1 = Mechanism(CKM_SHA_1)
MechanismRSAPKCS1 = Mechanism(CKM_RSA_PKCS)
MechanismRSAGENERATEKEYPAIR = Mechanism(CKM_RSA_PKCS_KEY_PAIR_GEN)
MechanismECGENERATEKEYPAIR = Mechanism(CKM_EC_KEY_PAIR_GEN)
MechanismAESGENERATEKEY = Mechanism(CKM_AES_KEY_GEN)

class RSAOAEPMechanism(Mechanism):
    def __init__(self, hashAlg, mgf, label=None):
        param = ck_rsa_pkcs_oaep_params(hashAlg, mgf, CKZ_DATA_SPECIFIED)
        self.label = label
        if label:
            param.source_data = byref(label)
            param.source_data_len = len(label)
        self._param = param
        super().__init__(CKM_RSA_PKCS_OAEP, addressof(param), sizeof(param))

class RSA_PSS_Mechanism(Mechanism):
    def __init__(self, mecha, hashAlg, mgf, sLen):
        param = ck_rsa_pkcs_pss_params(hashAlg, mgf, sLen)
        self._param = param
        super().__init__(mecha, addressof(param), sizeof(param))

class ECDH1_DERIVE_Mechanism(Mechanism):
    def __init__(self, publicData, kdf = CKD_NULL, sharedData = None):
        if sharedData is not None:
            sharedData = buffer(sharedData)
            sharedDataPtr = addressof(sharedData)
            sharedDataLen = len(sharedData)
        else:
            sharedDataPtr = None
            sharedDataLen = 0
        publicData = buffer(publicData)
        param = ck_ecdh1_derive_params(kdf, sharedDataLen, sharedDataPtr, len(publicData), addressof(publicData))
        self._param = param
        self._sharedData = sharedData
        self._publicData = publicData
        super().__init__(CKM_ECDH1_DERIVE, addressof(param), sizeof(param))

class AES_GCM_Mechanism(Mechanism):
    def __init__(self, iv, aad, tagBits):
        #void *pIv;
        #unsigned long ulIvLen;
        #unsigned long ulIvBits;
        #void *pAAD;
        #unsigned long ulAADLen;
        #unsigned long ulTagBits;
        self._source_iv = buffer(iv)
        self._source_aad = buffer(aad)
        ivbits = 0
        self._param = param = ck_gcm_params(
            addressof(self._source_iv), len(self._source_iv), ivbits,
            addressof(self._source_aad), len(self._source_aad), tagBits
        )
        super().__init__(CKM_AES_GCM, addressof(param), sizeof(param))
