#!/usr/bin/env vpython3
import ctypes as ct
from pkcsconfig import Config
from ctpkcs11 import pkcsapi, HSM, HSMError

class HSM(HSM):
    def displayInfo(self):
        print("Info for: {}".format(self.dllpath))
        print("\tfunctions version: {0}.{1}".format(self.funcs.version.major, self.funcs.version.minor))
        info = self.getInfo()
        print("\tversion: {0}.{1}".format(info.cryptokiVersion[0], info.cryptokiVersion[1]))
        print("\tmanufacturer:", info.manufacturerID)
        print("\tflags:", info.flags)
        print("\tdescription:", info.libraryDescription)
        print("\tlibrary version: {0}.{1}".format(info.libraryVersion[0], info.libraryVersion[1]))

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
                session.close()

    def displaySlotInfo(self, slot):
        info = self.getSlotInfo(slot)
        print("\tSlot number:{}".format(slot))
        print("\t\tDescription:", info.slotDescription)
        print("\t\tManufacturer_id:", info.manufacturerID)
        print("\t\tFlags:", info.flags)
        print("\t\tHardware version: {0}.{1}".format(info.hardwareVersion[0], info.hardwareVersion[1]))
        print("\t\tFirmware version: {0}.{1}".format(info.firmwareVersion[0], info.firmwareVersion[1]))

    def displayTokenInfo(self, slot):
        info = self.getTokenInfo(slot)
        print("\tToken:")
        print("\t\tlabel:", info.label)
        print("\t\tmanufacturer:", info.manufacturerID)
        print("\t\tmodel:", info.model)
        print("\t\tserial:", info.serialNumber)
        print("\t\tflags:", info.flags)
        print("\t\tmax_session_count:", info.ulMaxSessionCount, hex(info.ulMaxSessionCount))
        print("\t\tsession_count:", info.ulSessionCount)
        print("\t\tmax_rw_session_count:", info.ulMaxRwSessionCount)
        print("\t\trw_session_count:", info.ulRwSessionCount)
        print("\t\tmax_pin_len:", info.ulMaxPinLen)
        print("\t\tmin_pin_len:", info.ulMinPinLen)
        print("\t\ttotal_public_memory:", info.ulTotalPublicMemory)
        print("\t\tfree_public_memory:", info.ulFreePublicMemory)
        print("\t\ttotal_private_memory:", info.ulTotalPrivateMemory)
        print("\t\tfree_private_memory:", info.ulFreePrivateMemory)
        print("\t\thardware: {0}.{1}".format(info.hardwareVersion[0], info.hardwareVersion[1]))
        print("\t\tfirmware: {0}.{1}".format(info.firmwareVersion[0], info.firmwareVersion[1]))
        print("\t\ttime:", info.utcTime)
        return True

    def displaySlotObjects(self, hsession):
        print("\tObjects:")
        rc = self.funcs.C_FindObjectsInit(hsession, None, 0)
        if rc != pkcsapi.CKR_OK:
            raise HSMError(rc, "C_FindObjectsInit")
        SearchResult = (pkcsapi.ck_object_handle_t * 30)()
        maxobj = pkcsapi.c_ulong(0)
        try:
            while True:
                rc = self.funcs.C_FindObjects(hsession, ct.byref(SearchResult), len(SearchResult), ct.byref(maxobj))
                if rc != pkcsapi.CKR_OK or maxobj.value == 0:
                    break
                # if rc == pkcsapi.CKR_OK and maxobj.value > 0:
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
            pkcsapi.CKR_ATTRIBUTE_SENSITIVE: "sensitive",
            pkcsapi.CKR_ATTRIBUTE_TYPE_INVALID: "invalid type",
            pkcsapi.CKR_ATTRIBUTE_VALUE_INVALID: "invalid value",
        }
        for value, name in pkcsapi.CKA.items():
            if type(value) == str:
                continue
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
                    "\t\t\t====C_GetAttributeValue({})={:x} type:{} len:{}".format(name, rc, t.type, t.value_len),
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
                print("{} ({})".format(pkcsapi.CKO[buf.cint], tvalue))
            elif value == pkcsapi.CKA_CERTIFICATE_TYPE:
                print("{} ({})".format(pkcsapi.CKC[buf.cint], tvalue))
            elif value == pkcsapi.CKA_KEY_TYPE:
                print("{} ({})".format(pkcsapi.CKK[buf.cint], tvalue))
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
                        s = buf.cbyte[: t.value_len]
                        print(s, "(bytes)")
def main():
    cfg = Config()
    cls = HSM(cfg.dllpath)
    cls.open()
    try:
        cls.displayInfo()
        cls.displaySlots(0, cfg.pin)
        cls.displaySlots(1, cfg.pin)
    finally:
        cls.close()

main()
