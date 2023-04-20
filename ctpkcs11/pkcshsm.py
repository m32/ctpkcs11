#!/usr/bin/env vpython3
import ctypes as ct
from . import pkcsapi, pkcspacking

called = None
#called = {}
if called is not None:
    import pickle
    try:
        with open('functions.called', 'rb')as fp:
            called = pickle.loads(fp.read())
    except:
        for data in pkcsapi.ck_function_list._fields_:
            called[data[0]] = False

class HSMError(Exception):
    def __init__(self, rc, func):
        self.rc = rc
        self.func = func

    def __repr__(self):
        return "HSMError: function:{} error:{}({})".format(self.func, self.rc, pkcsapi.CKR.get(self.rc, "unknown"))

    __str__ = __repr__


class DigestSession(object):
    def __init__(self, hsm, hsession, mecha):
        self.hsm = hsm
        self.hsession = hsession
        rc = self.hsm.funcs.C_DigestInit(self.hsession, ct.byref(mecha))
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_DigestInit")

    def update(self, data):
        data1 = pkcsapi.buffer(data)
        rc = self.hsm.funcs.C_DigestUpdate(self.hsession, ct.byref(data1), len(data1))
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_DigestUpdate")
        return self

    def digestKey(self, handle):
        rc = self.hsm.funcs.C_DigestKey(self.hsession, handle)
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_DigestKey")
        return self

    def final(self):
        ddatalen = ct.c_ulong(0)
        # Get the size of the digest
        rc = self.hsm.funcs.C_DigestFinal(self.hsession, None, ct.byref(ddatalen))
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_DigestFinal")
        # Get the actual digest
        ddata = pkcsapi.buffer(ddatalen.value)
        rc = self.hsm.funcs.C_DigestFinal(self.hsession, ct.byref(ddata), ct.byref(ddatalen))
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_DigestFinal")
        return bytes(ddata)

class Session:
    def __init__(self, hsm, hsession):
        self.hsm = hsm
        self.hsession = hsession

    def close(self):
        rc = self.hsm.funcs.C_CloseSession(self.hsession)
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_CloseSession")
        self.hsession = None
        self.hsm = None

    def login(self, pin, user_type=pkcsapi.CKU_USER):
        if type(pin) == str:
            pin = pin.encode("utf8")
        rc = self.hsm.funcs.C_Login(self.hsession, user_type, pin, len(pin))
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_Login")

    def logout(self):
        rc = self.hsm.funcs.C_Logout(self.hsession)
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_Logout")

    def setPin(self, old_pin, new_pin):
        if type(old_pin) == str:
            old_pin = old_pin.encode("utf8")
        if type(new_pin) == str:
            new_pin = new_pin.encode("utf8")
        rc = self.hsm.funcs.C_SetPIN(self.hsession, old_pin, len(old_pin), new_pin, len(new_pin))
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_SetPIN")

    def initPin(self, pin):
        if type(pin) == str:
            pin = pin.encode("utf8")
        rc = self.hsm.funcs.C_InitPIN(self.hsession, pin, len(pin))
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_InitPIN")

    def generateKeyPair(self, templatePub, templatePriv, mecha=pkcsapi.MechanismRSAGENERATEKEYPAIR):
        rpuattr, rpubuf = pkcspacking.pack(templatePub)
        rprattr, rprbuf = pkcspacking.pack(templatePriv)
        ck_pub_handle = pkcsapi.ck_object_handle_t()
        ck_prv_handle = pkcsapi.ck_object_handle_t()
        rc = self.hsm.funcs.C_GenerateKeyPair(
            self.hsession,
            mecha,
            rpuattr,
            len(rpuattr),
            rprattr,
            len(rprattr),
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

    def getAttributeValue(self, handle, attrs, allAsBinary=False):
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

    def generateKey(self, template, mecha=pkcsapi.MechanismAESGENERATEKEY):
        attrs, attrsbuf = pkcspacking.pack(template)
        handle = pkcsapi.ck_object_handle_t()
        rc = self.hsm.funcs.C_GenerateKey(self.hsession, ct.byref(mecha), ct.byref(attrs), len(attrs), ct.byref(handle))
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, 'C_GenerateKey')
        return handle.value

    def wrapKey(self, wrappingKey, key, mecha=pkcsapi.MechanismRSAPKCS1):
        wraplen = ct.c_ulong(0)
        rc = self.hsm.funcs.C_WrapKey(self.hsession, ct.byref(mecha), wrappingKey, key, None, ct.byref(wraplen))
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, 'C_WrapKey')
        wrapped = pkcsapi.buffer(wraplen.value)
        rc = self.hsm.funcs.C_WrapKey(
            self.hsession, ct.byref(mecha), wrappingKey, key, ct.byref(wrapped), ct.byref(wraplen)
        )
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, 'C_WrapKey')
        return bytes(wrapped)

    def unwrapKey(self, unwrappingKey, wrappedKey, template, mecha=pkcsapi.MechanismRSAPKCS1):
        attrs, attrsbuf = pkcspacking.pack(template)
        handle = pkcsapi.ck_object_handle_t()
        wrapped = pkcsapi.buffer(wrappedKey)
        rc = self.hsm.funcs.C_UnwrapKey(
            self.hsession,
            ct.byref(mecha),
            unwrappingKey,
            ct.byref(wrapped),
            len(wrapped),
            attrs,
            len(attrs),
            ct.byref(handle),
        )
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, 'C_UnwrapKey')
        return handle.value

    def deriveKey(self, baseKey, template, mecha):
        attrs, attrsbuf = pkcspacking.pack(template)
        handle = pkcsapi.ck_object_handle_t()
        rc = self.hsm.funcs.C_DeriveKey(
            self.hsession, ct.byref(mecha), baseKey, ct.byref(attrs), len(attrs), ct.byref(handle)
        )
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, 'C_DeriveKey')
        return handle.value

    def sign(self, privKey, data, mecha=pkcsapi.MechanismRSAPKCS1):
        rc = self.hsm.funcs.C_SignInit(self.hsession, ct.byref(mecha), privKey)
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_SignInit")
        datasig = pkcsapi.buffer(data)
        siglen = ct.c_ulong(0)
        rc = self.hsm.funcs.C_Sign(self.hsession, ct.byref(datasig), len(data), None, ct.byref(siglen))
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_Sign")
        signature = pkcsapi.buffer(siglen.value)
        rc = self.hsm.funcs.C_Sign(self.hsession, ct.byref(datasig), len(data), ct.byref(signature), ct.byref(siglen))
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_Sign")
        return bytes(signature)

    def verify(self, key, data, signature, mecha=pkcsapi.MechanismRSAPKCS1):
        rc = self.hsm.funcs.C_VerifyInit(self.hsession, ct.byref(mecha), key)
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_VerifyInit")
        bdata = pkcsapi.buffer(data)
        bsignature = pkcsapi.buffer(signature)
        rc = self.hsm.funcs.C_Verify(self.hsession, ct.byref(bdata), len(data), ct.byref(bsignature), len(signature))
        if rc == pkcsapi.CKR_OK:
            return True
        elif rc == pkcsapi.CKR_SIGNATURE_INVALID:
            return False
        raise HSMError(rc, "C_Verify")

    def encrypt(self, key, data, mecha=pkcsapi.MechanismRSAPKCS1):
        rc = self.hsm.funcs.C_EncryptInit(self.hsession, ct.byref(mecha), key)
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_EncryptInit")
        bdata = pkcsapi.buffer(data)
        edatalen = ct.c_ulong(0)
        rc = self.hsm.funcs.C_Encrypt(self.hsession, ct.byref(bdata), len(bdata), None, ct.byref(edatalen))
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_Encrypt")
        edata = pkcsapi.buffer(edatalen.value)
        rc = self.hsm.funcs.C_Encrypt(self.hsession, ct.byref(bdata), len(bdata), ct.byref(edata), ct.byref(edatalen))
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_Encrypt")
        return bytes(edata)

    def decrypt(self, key, data, mecha=pkcsapi.MechanismRSAPKCS1):
        rc = self.hsm.funcs.C_DecryptInit(self.hsession, ct.byref(mecha), key)
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_DecryptInit")
        bdata = pkcsapi.buffer(data)
        ddatalen = ct.c_ulong(0)
        rc = self.hsm.funcs.C_Decrypt(self.hsession, ct.byref(bdata), len(bdata), None, ct.byref(ddatalen))
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_Decrypt")
        ddata = pkcsapi.buffer(ddatalen.value)
        rc = self.hsm.funcs.C_Decrypt(self.hsession, ct.byref(bdata), len(bdata), ct.byref(ddata), ct.byref(ddatalen))
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_Decrypt")
        return bytes(ddata[: ddatalen.value])

    def digestSession(self, mecha=pkcsapi.MechanismSHA1):
        return DigestSession(self.hsm, self.hsession, mecha)

    def digest(self, data, mecha=pkcsapi.MechanismSHA1):
        rc = self.hsm.funcs.C_DigestInit(self.hsession, ct.byref(mecha))
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_DigestInit")
        data1 = pkcsapi.buffer(data)
        ddatalen = ct.c_ulong(0)
        # first call get digest size
        rc = self.hsm.funcs.C_Digest(self.hsession, ct.byref(data1), len(data1), None, ct.byref(ddatalen))
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_Digest")
        ddata = pkcsapi.buffer(ddatalen.value)
        # second call get actual digest data
        rc = self.hsm.funcs.C_Digest(self.hsession, ct.byref(data1), len(data1), ct.byref(ddata), ct.byref(ddatalen))
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_Digest")
        return bytes(ddata)

    def seedRandom(self, seed):
        ctseed = pkcsapi.buffer(seed)
        rc = self.hsm.funcs.C_SeedRandom(self.hsession, ct.byref(ctseed), len(seed))
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_SeedRandom")

    def generateRandom(self, size=16):
        ctrand = pkcsapi.buffer(size)
        rc = self.hsm.funcs.C_GenerateRandom(self.hsession, ct.byref(ctrand), size)
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_GenerateRandom")
        return bytes(ctrand)

    def getSessionInfo(self):
        sessioninfo = pkcsapi.ck_session_info()
        rc = self.hsm.funcs.C_GetSessionInfo(self.hsession, ct.byref(sessioninfo))
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_GetSessionInfo")
        class Info:
            slotID = sessioninfo.slot_id
            state = sessioninfo.state
            flags = sessioninfo.flags
            ulDeviceError = sessioninfo.device_error
        return Info()


    def displaySessionInfo(self):
        sessioninfo = self.getSessionInfo()
        print(
            "\tC_GetSessionInfo: slot_id={}, state={} flags={}, device_error={}".format(
                sessioninfo.slotID, sessioninfo.state, sessioninfo.flags, sessioninfo.ulDeviceError
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
        if called is not None:
            class XX:
                def __getattr__(self, name):
                    called[name] = True
                    return getattr(pfuncs.contents, name)
            self.funcs = XX()

    def open(self):
        rc = self.funcs.C_Initialize(None)
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_Initialize")

    def close(self):
        rc = self.funcs.C_Finalize(None)
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_Finalize")
        if called is not None:
            with open('functions.called', 'wb') as fp:
                fp.write(pickle.dumps(called))

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
        sopin = sopin.encode("utf8")
        label = label.encode("utf8")
        rc = self.funcs.C_InitToken(slot, sopin, len(sopin), label)
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_InitToken")

    def getTokenInfo(self, slot):
        tokeninfo = pkcsapi.ck_token_info()
        rc = self.funcs.C_GetTokenInfo(slot, ct.byref(tokeninfo))
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_GetTokenInfo")

        def strg(data):
            data = bytes(data).decode("utf8")
            data = data.replace("\0", " ").strip()
            return data
        def intg(data):
            #if data == pkcsapi.CK_UNAVAILABLE_INFORMATION:
            if data == 0xFFFFFFFFFFFFFFFF:
                data = -1
            return data

        class Info:
            label = strg(tokeninfo.label)
            manufacturerID = strg(tokeninfo.manufacturer_id)
            model = strg(tokeninfo.model)
            serialNumber = strg(tokeninfo.serial_number)
            flags = tokeninfo.flags
            ulMaxSessionCount = intg(tokeninfo.max_session_count)
            ulSessionCount = intg(tokeninfo.session_count)
            ulMaxRwSessionCount = intg(tokeninfo.max_rw_session_count)
            ulRwSessionCount = intg(tokeninfo.rw_session_count)
            ulMaxPinLen = tokeninfo.max_pin_len
            ulMinPinLen = tokeninfo.min_pin_len
            ulTotalPublicMemory = intg(tokeninfo.total_public_memory)
            ulFreePublicMemory = intg(tokeninfo.free_public_memory)
            ulTotalPrivateMemory = intg(tokeninfo.total_private_memory)
            ulFreePrivateMemory = intg(tokeninfo.free_private_memory)
            hardwareVersion = (tokeninfo.hardware_version.major, tokeninfo.hardware_version.minor)
            firmwareVersion = (tokeninfo.firmware_version.major, tokeninfo.firmware_version.minor)
            utcTime = strg(tokeninfo.utc_time)
        return Info()

    def openSession(self, slot, flags=pkcsapi.CKF_SERIAL_SESSION | pkcsapi.CKF_RW_SESSION):
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

    def closeAllSessions(self, slot):
        rc = self.funcs.C_CloseAllSessions(slot)
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_OpenSession")

    def getMechanismList(self, slot):
        nmech = ct.c_ulong(0)
        rc = self.funcs.C_GetMechanismList(slot, None, ct.byref(nmech))
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_GetMechanismList")
        mechs = (pkcsapi.ck_mechanism_type_t * nmech.value)()
        rc = self.funcs.C_GetMechanismList(slot, ct.byref(mechs), ct.byref(nmech))
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_GetMechanismList")
        result = []
        for mechanism in mechs:
            if mechanism >= pkcsapi.CKM_VENDOR_DEFINED:
                k = "CKM_VENDOR_DEFINED_0x%X" % (mechanism - pkcsapi.CKM_VENDOR_DEFINED)
                pkcsapi.CKM[k] = mechanism
                pkcsapi.CKM[mechanism] = k
            else:
                try:
                    k = pkcsapi.CKM[mechanism]
                except KeyError:
                    k = "CKM_UNKNOWN_0x%X" % mechanism
                    pkcsapi.CKM[mechanism] = k
                    pkcsapi.CKM[k] = mechanism
            result.append(mechanism)
        return result

    def getMechanismInfo(self, slot, mech):
        info = pkcsapi.ck_mechanism_info()
        rc = self.funcs.C_GetMechanismInfo(slot, mech, ct.byref(info))
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_GetMechanismInfo")
        return info

    def getInfo(self):
        info = pkcsapi.ck_info()
        rc = self.funcs.C_GetInfo(ct.byref(info))
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_GetInfo")

        class Info:
            cryptokiVersion = (info.cryptoki_version.major, info.cryptoki_version.minor)
            manufacturerID = bytes(info.manufacturer_id).decode("ascii").strip()
            flags = info.flags
            libraryDescription = bytes(info.library_description).decode("ascii").strip()
            libraryVersion = (info.library_version.major, info.library_version.minor)
        return Info()

    def getSlotInfo(self, slot):
        slotinfo = pkcsapi.ck_slot_info()
        rc = self.funcs.C_GetSlotInfo(slot, ct.byref(slotinfo))
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_GetSlotInfo")
        class Info:
            slotDescription = bytes(slotinfo.slot_description).decode("ascii").strip()
            manufacturerID = bytes(slotinfo.manufacturer_id).decode("ascii").strip()
            flags = slotinfo.flags
            hardwareVersion = (slotinfo.hardware_version.major, slotinfo.hardware_version.minor)
            firmwareVersion = (slotinfo.firmware_version.major, slotinfo.firmware_version.minor)
        return Info()
