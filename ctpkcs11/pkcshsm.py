#!/usr/bin/env vpython3
import ctypes as ct
from . import pkcsapi, pkcspacking

class HSMError(Exception):
    def __init__(self, rc,  func):
        self.rc = rc
        self.func = func
    def __repr__(self):
        return 'HSMError: function:{} error:{}({})'.format(self.func, self.rc, pkcsapi.CKR.get(self.rc, 'unknown'))
    __str__ = __repr__

MechanismSHA1 = pkcsapi.Mechanism(pkcsapi.CKM_SHA_1)
MechanismRSAPKCS1 = pkcsapi.Mechanism(pkcsapi.CKM_RSA_PKCS)
MechanismRSAGENERATEKEYPAIR = pkcsapi.Mechanism(pkcsapi.CKM_RSA_PKCS_KEY_PAIR_GEN)
MechanismECGENERATEKEYPAIR = pkcsapi.Mechanism(pkcsapi.CKM_EC_KEY_PAIR_GEN)
MechanismAESGENERATEKEY = pkcsapi.Mechanism(pkcsapi.CKM_AES_KEY_GEN)

def buffer(data):
    if type(data) == int:
        bdata = ct.create_string_buffer(data)
    else:
        bdata = ct.create_string_buffer(len(data))
        bdata.value = data
    return bdata

class Session:
    def __init__(self, hsm, hsession):
        self.hsm = hsm
        self.hsession = hsession

    def closeSession(self):
        rc = self.hsm.funcs.C_CloseSession(self.hsession)
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_CloseSession")
        self.hsession = None
        self.hsm = None

    def login(self, pin, user_type=pkcsapi.CKU_USER):
        if type(pin) == str:
            pin = pin.encode('utf8')
        rc = self.hsm.funcs.C_Login(self.hsession, user_type, pin, len(pin))
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_Login")

    def logout(self):
        rc = self.hsm.funcs.C_Logout(self.hsession)
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_Logout")

    def initPin(self, pin):
        pin = pin.encode('utf8')
        rc = self.hsm.funcs.C_InitPIN(self.hsession, pin, len(pin))
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_InitPIN")

    def generateKeyPair(self, templatePub, templatePriv, mecha=MechanismRSAGENERATEKEYPAIR):
        rpuattr, rpubuf = pkcspacking.pack(templatePub)
        rprattr, rprbuf = pkcspacking.pack(templatePriv)
        ck_pub_handle = pkcsapi.ck_object_handle_t()
        ck_prv_handle = pkcsapi.ck_object_handle_t()
        rc = self.hsm.funcs.C_GenerateKeyPair(
            self.hsession, mecha,
            rpuattr, len(rpuattr),
            rprattr, len(rprattr),
            ct.byref(ck_pub_handle),
            ct.byref(ck_prv_handle),
        )
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_GenerateKeyPair")
        return ck_pub_handle.value, ck_prv_handle.value

    def createObject(self, template):
        rattr, rbuf = pkcspacking.pack(template)
        handle = pkcsapi.ck_object_handle_t()
        rc = self.hsm.funcs.C_CreateObject(self.hsession, rattr, len(rattr), ct.byref(handle))
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_CreateObject")
        return handle.value

    def destroyObject(self, obj):
        rc = self.hsm.funcs.C_DestroyObject(self.hsession, obj)
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_DestroyObject")

    def findObjects(self, attrs):
        # [(PK11.CKA_CLASS, PK11.CKO_PRIVATE_KEY), (PK11.CKA_ID, keyid)]
        if len(attrs) == 0:
            raise HSMError(rc, "findObjects")
        rattr, rbuf = pkcspacking.pack(attrs)
        rc = self.hsm.funcs.C_FindObjectsInit(self.hsession, rattr, len(rattr))
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_FindObjectsInit")
        SearchResult = (pkcsapi.ck_object_handle_t * 30)()
        maxobj = pkcsapi.c_ulong(0)
        result = []
        try:
            rc = self.hsm.funcs.C_FindObjects(
                self.hsession, ct.byref(SearchResult), len(SearchResult), ct.byref(maxobj)
            )
            if rc != pkcsapi.CKR_OK:
                raise HSMError(rc, "C_FindObjects")
            for i in range(maxobj.value):
                handle = SearchResult[i]
                result.append(handle)
        finally:
            rc = self.hsm.funcs.C_FindObjectsFinal(self.hsession)
            if rc != pkcsapi.CKR_OK:
                raise HSMError(rc, "C_FindObjectsFinal")
        return result

    def getAttributeValue(self, handle, attrs):
        def getbuf(n):
            class U(ct.Union):
                _fields_ = (
                    ("cint", ct.c_uint),
                    ("cbool", ct.c_ubyte),
                    ("cchar", ct.c_char * n),
                    ("cbyte", ct.c_ubyte * n),
                )

            return U()

        result = []
        buf = getbuf(16384)
        t = pkcsapi.ck_attribute(0, ct.addressof(buf), 0)
        for attr in attrs:
            t.type = attr
            t.value_len = ct.sizeof(buf)
            rc = self.hsm.funcs.C_GetAttributeValue(self.hsession, handle, ct.byref(t), 1)
            if rc != pkcsapi.CKR_OK:
                raise HSMError(rc, "C_GetAttributeValue")
            if t.value_len > ct.sizeof(buf):
                buf = getbuf(t.value_len + 1 + ct.sizeof(pkcsapi.ck_attribute))
                t = pkcsapi.ck_attribute(0, ct.addressof(buf), ct.sizeof(buf))
                rc = self.hsm.funcs.C_GetAttributeValue(self.hsession, handle, ct.byref(t), 1)
                if rc != pkcsapi.CKR_OK:
                    raise HSMError(rc, "C_GetAttributeValue")
            v = pkcspacking.unpack(t)
            result.append(v)
        return result

    def sign(self, privKey, data, mech=MechanismRSAPKCS1):
        rc = self.hsm.funcs.C_SignInit(self.hsession, ct.byref(mech), privKey)
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_SignInit")
        datasig = buffer(data)
        siglen = ct.c_ulong(0)
        # first call get signature size
        rc = self.hsm.funcs.C_Sign(self.hsession, ct.byref(datasig), len(data), None, ct.byref(siglen))
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_Sign")
        # second call get actual signature data
        signature = buffer(siglen.value)
        rc = self.hsm.funcs.C_Sign(self.hsession, ct.byref(datasig), len(data), ct.byref(signature), ct.byref(siglen))
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_Sign")
        #return bytearray(signature)
        return bytes(signature)

    def verify(self, key, data, signature, mech=MechanismRSAPKCS1):
        rc = self.hsm.funcs.C_VerifyInit(self.hsession, ct.byref(mech), key)
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_VerifyInit")
        bdata = buffer(data)
        bsignature = buffer(signature)
        rc = self.hsm.funcs.C_Verify(self.hsession, ct.byref(bdata), len(data), ct.byref(bsignature), len(signature))
        if rc == pkcsapi.CKR_OK:
            return True
        elif rc == pkcsapi.CKR_SIGNATURE_INVALID:
            return False
        raise HSMError(rc, "C_Verify")

    def encrypt(self, key, data, mech=MechanismRSAPKCS1):
        rc = self.hsm.funcs.C_EncryptInit(self.hsession, ct.byref(mech), key)
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_EncryptInit")
        bdata = buffer(data)
        edatalen = ct.c_ulong(0)
        rc = self.hsm.funcs.C_Encrypt(self.hsession, ct.byref(bdata), len(bdata), None, ct.byref(edatalen))
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_Encrypt")
        edata = buffer(edatalen.value)
        rc = self.hsm.funcs.C_Encrypt(self.hsession, ct.byref(bdata), len(bdata), ct.byref(edata), ct.byref(edatalen))
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_Encrypt")
        return bytes(edata)

    def decrypt(self, key, data, mech=MechanismRSAPKCS1):
        rc = self.hsm.funcs.C_DecryptInit(self.hsession, ct.byref(mech), key)
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_DecryptInit")
        bdata = buffer(data)
        ddatalen = ct.c_ulong(0)
        rc = self.hsm.funcs.C_Decrypt(self.hsession, ct.byref(bdata), len(bdata), None, ct.byref(ddatalen))
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_Decrypt")
        ddata = buffer(ddatalen.value)
        rc = self.hsm.funcs.C_Decrypt(self.hsession, ct.byref(bdata), len(bdata), ct.byref(ddata), ct.byref(ddatalen))
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_Decrypt")
        return bytes(ddata[:ddatalen.value])

    def displaySessionInfo(self):
        sessioninfo = pkcsapi.ck_session_info()
        rc = self.hsm.funcs.C_GetSessionInfo(self.hsession, ct.byref(sessioninfo))
        print(
            "\tC_GetSessionInfo={0} slot_id={1}, state={2} flags={3}, device_error={4}".format(
                rc, sessioninfo.slot_id, sessioninfo.state, sessioninfo.flags, sessioninfo.device_error
            )
        )

class HSM:
    def __init__(self, dllpath):
        self.lhsm = ct.CDLL(dllpath)

        pfuncs = ct.POINTER(pkcsapi.ck_function_list)()
        rc = self.lhsm.C_GetFunctionList(ct.byref(pfuncs))
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_GetFunctionList")
        self.dllpath = dllpath
        self.funcs = pfuncs.contents

    def open(self):
        rc = self.funcs.C_Initialize(None)
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_Initialize")

    def close(self):
        rc = self.funcs.C_Finalize(None)
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_Finalize")

    def getSlotList(self, tokenPresent):
        tokenPresent = 1 if tokenPresent else 0
        nslots = ct.c_ulong()
        rc = self.funcs.C_GetSlotList(tokenPresent, None, ct.byref(nslots))
        if rc != pkcsapi.CKR_OK or nslots.value == 0:
            raise HSMError(rc, "C_GetSlotList")
        slot_list = (pkcsapi.ck_slot_id_t * nslots.value)()
        rc = self.funcs.C_GetSlotList(tokenPresent, ct.byref(slot_list), ct.byref(nslots))
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_GetSlotList")
        return slot_list

    def initToken(self, slot, sopin, label):
        sopin = sopin.encode('utf8')
        label = label.encode('utf8')
        rc = self.funcs.C_InitToken(slot, sopin, len(sopin), label)
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_InitToken")

    def getTokenInfo(self, slot):
        tokeninfo = pkcsapi.ck_token_info()
        rc = self.funcs.C_GetTokenInfo(slot, ct.byref(tokeninfo))
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_GetTokenInfo")
        class Info:
            pass
        info = Info()
        for fname, ftype in tokeninfo._fields_:
            data =  getattr(tokeninfo, fname)
            if fname in ('label', 'manufacturer_id', 'model', 'serial_number', 'utc_time'):
                data = bytes(data).decode("ascii")
                data = data.replace('\0', ' ').strip()
            elif fname in ('max_session_count', 'session_count', 'max_rw_session_count', 'rw_session_count', 'total_public_memory', 'free_public_memory', 'total_private_memory', 'free_private_memory'):
                #if data == pkcsapi.CK_UNAVAILABLE_INFORMATION:
                if data == 0xffffffffffffffff:
                    data = -1
            setattr(info, fname, data)
        return info

    def openSession(self, slot, flags=pkcsapi.CKF_SERIAL_SESSION|pkcsapi.CKF_RW_SESSION):
        hsession = pkcsapi.ck_session_handle_t()
        rc = self.funcs.C_OpenSession(
            slot,
            flags,
            None,
            pkcsapi.ck_notify_t(0),
            ct.byref(hsession),
        )
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_OpenSession")
        return Session(self, hsession)

    def displayInfo(self):
        print("Info for: {}".format(self.dllpath))
        print("\tfunctions version: {0}.{1}".format(self.funcs.version.major, self.funcs.version.minor))
        info = pkcsapi.ck_info()
        rc = self.funcs.C_GetInfo(ct.byref(info))
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_GetInfo")
        print("\tversion: {0}.{1}".format(info.cryptoki_version.major, info.cryptoki_version.minor))
        print("\tmanufacturer:", bytes(info.manufacturer_id).decode("ascii").strip())
        print("\tflags:", info.flags)
        print("\tdescription:", bytes(info.library_description).decode("ascii").strip())
        print("\tlibrary version: {0}.{1}".format(info.library_version.major, info.library_version.minor))

    def displaySlotInfo(self, slot):
        slotinfo = pkcsapi.ck_slot_info()
        rc = self.funcs.C_GetSlotInfo(slot, ct.byref(slotinfo))
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_GetSlotInfo")
        print("\tSlot number:{}".format(slot))
        print("\t\tDescription:", bytes(slotinfo.slot_description).decode("ascii").strip())
        print("\t\tManufacturer_id:", bytes(slotinfo.manufacturer_id).decode("ascii").strip())
        print("\t\tFlags:", slotinfo.flags)
        print("\t\tHardware version: {0}.{1}".format(slotinfo.hardware_version.major, slotinfo.hardware_version.minor))
        print("\t\tFirmware version: {0}.{1}".format(slotinfo.firmware_version.major, slotinfo.firmware_version.minor))

    def displayTokenInfo(self, slot):
        info = self.getTokenInfo(slot)
        print("\tToken:")
        print("\t\tlabel:", info.label)
        print("\t\tmanufacturer:",info.manufacturer_id)
        print("\t\tmodel:", info.model)
        print("\t\tserial:", info.serial_number)
        print("\t\tflags:", info.flags)
        print("\t\tmax_session_count:", info.max_session_count, hex(info.max_session_count))
        print("\t\tsession_count:", info.session_count)
        print("\t\tmax_rw_session_count:", info.max_rw_session_count)
        print("\t\trw_session_count:", info.rw_session_count)
        print("\t\tmax_pin_len:", info.max_pin_len)
        print("\t\tmin_pin_len:", info.min_pin_len)
        print("\t\ttotal_public_memory:", info.total_public_memory)
        print("\t\tfree_public_memory:", info.free_public_memory)
        print("\t\ttotal_private_memory:", info.total_private_memory)
        print("\t\tfree_private_memory:", info.free_private_memory)
        print("\t\thardware: {0}.{1}".format(info.hardware_version.major, info.hardware_version.minor))
        print("\t\tfirmware: {0}.{1}".format(info.firmware_version.major, info.firmware_version.minor))
        print("\t\ttime:", info.utc_time)
        return True

    def displaySlots(self, tokenpresent, pin):
        print("Slots(tpkenpresent={})".format(tokenpresent))
        slot_list = self.getSlotList(tokenpresent)
        for slot in slot_list:
            self.displaySlotInfo(slot)
            self.displayTokenInfo(slot)
            try:
                session = self.openSession(slot)
            except HSMError as ex:
                if ex.rc == pkcsapi.CKR_TOKEN_NOT_RECOGNIZED:
                    continue
                raise
            try:
                session.login(pin)
                try:
                    self.displaySlotObjects(session.hsession)
                finally:
                    session.logout()
            finally:
                session.closeSession()

    def displaySlotObjects(self, hsession):
        print("\tObjects:")
        rc = self.funcs.C_FindObjectsInit(hsession, None, 0)
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_FindObjectsInit")
        SearchResult = (pkcsapi.ck_object_handle_t * 30)()
        maxobj = pkcsapi.c_ulong(0)
        try:
            while True:
                rc = self.funcs.C_FindObjects(
                    hsession, ct.byref(SearchResult), len(SearchResult), ct.byref(maxobj)
                )
                if rc != pkcsapi.CKR_OK or maxobj.value == 0:
                    break
                #if rc == pkcsapi.CKR_OK and maxobj.value > 0:
                for i in range(maxobj.value):
                    self.displaySlotAttributes(hsession, SearchResult[i])
        finally:
            rc = self.funcs.C_FindObjectsFinal(hsession)
            if rc != pkcsapi.CKR_OK:
                raise HSMError(rc, "C_FindObjectsFinal")

    def displaySlotAttributes(self, hsession, hobject):
        print("\t\thobject=0x{:x}".format(hobject))
        def getbuf(n):
            class U(ct.Union):
                _fields_ = (
                    ("cint", ct.c_uint),
                    ("cbool", ct.c_ubyte),
                    ("cchar", ct.c_char * n),
                    ("cbyte", ct.c_ubyte * n),
                )

            return U()

        buf = getbuf(16384)
        t = pkcsapi.ck_attribute(0, ct.addressof(buf), 0)
        # t.value = addressof(buf)
        disabledby = {
            pkcsapi.CKR_ATTRIBUTE_SENSITIVE: 'sensitive',
            pkcsapi.CKR_ATTRIBUTE_TYPE_INVALID: 'invalid type',
            pkcsapi.CKR_ATTRIBUTE_VALUE_INVALID: 'invalid value',
        }
        for value, name in pkcsapi.CKA.items():
            t.type = value
            t.value_len = ct.sizeof(buf)
            rc = self.funcs.C_GetAttributeValue(hsession, hobject, ct.byref(t), 1)
            if rc == pkcsapi.CKR_ATTRIBUTE_SENSITIVE:
                print("\t\t\t", name, "(", t.type, ") disabled because", disabledby[rc])
            if rc in (
                pkcsapi.CKR_ATTRIBUTE_SENSITIVE,
                pkcsapi.CKR_ATTRIBUTE_TYPE_INVALID,
                pkcsapi.CKR_ATTRIBUTE_VALUE_INVALID,
            ):
                continue
            if rc != pkcsapi.CKR_OK:
                print(
                    "\t\t\t====C_GetAttributeValue({})={:x} type:{} len:{}".format(
                        name, rc, t.type, t.value_len
                    ),
                )
                continue
            if t.value_len > ct.sizeof(buf):
                buf = getbuf(t.value_len + 1)
                t = pkcsapi.ck_attribute(0, ct.addressof(buf), ct.sizeof(buf))
                rc = self.funcs.C_GetAttributeValue(hsession, hobject, ct.byref(t), 1)
                if rc != pkcsapi.CKR_OK:
                    raise HSMError(rc, "C_GetAttributeValue")
            try:
                tvalue = pkcspacking.unpack(t)
            except:
                tvalue = None
            print("\t\t\t{}({})=".format(name, t.type), end=" ")
            if value == pkcsapi.CKA_CLASS:
                print('{} ({})'.format(pkcsapi.CKO[buf.cint], tvalue))
            elif value == pkcsapi.CKA_CERTIFICATE_TYPE:
                print('{} ({})'.format(pkcsapi.CKC[buf.cint], tvalue))
            elif value == pkcsapi.CKA_KEY_TYPE:
                print('{} ({})'.format(pkcsapi.CKK[buf.cint], tvalue))
            else:
                if tvalue is not None:
                    print(tvalue)
                else:
                    if t.type in pkcsapi.AttrIsBool:
                        print(buf.cbool, "(bool)")
                    elif t.type in pkcsapi.AttrIsNum:
                        print(buf.cint, "(int)")
                    elif t.type in pkcsapi.AttrIsString:
                        s = buf.cchar[: t.value_len]
                        print(s, "(string)")
                    elif t.type in pkcsapi.AttrIsList:
                        s = buf.cbyte[: t.value_len]
                        print(s, "(list)")
                    else:
                        s= buf.cbyte[: t.value_len]
                        print(s, "(bytes)")
