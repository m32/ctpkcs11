#!/usr/bin/env vpython3
import sys
sys.path.insert(1, '..')
from ctpkcs11 import api

def _CK_DECLARE_FUNCTION(cdef):
    cdef = ' '.join(cdef.split())
    funcname, funcdef = cdef.split(', ', 1)
    assert funcdef[0] == '(' and funcdef[-1] == ')'
    funcargs = funcdef[1:-1].split(', ')
    args = ['ck_rv_t']
    for cdef in funcargs:
        assert ',' not in cdef
        cdef = cdef.split()
        if cdef[0] == "unsigned":
            # unsigned [char|int|long int] [*] <varname>;
            t = {"char": 'c_ubyte', "int": 'c_uint', "long": 'c_ulong'}
            ctype = t[cdef[1]]
            if cdef[1] == "long" and cdef[2] == "int":
                cdef = cdef[3:]
            else:
                cdef = cdef[2:]
            cdef = "".join(cdef)
            #print('*'*20, cdef, ctype)
            if ctype == 'c_ubyte' and cdef[0] == '*':
                ctype = 'c_void_p'
                cdef = cdef[1:]
            else:
                cdef = [cdef]
        else:
            if cdef[0] == "struct":
                # struct <name> * <varname>
                #ctype = aliases[cdef[1]]
                ctype = cdef[1]
                cdef = "".join(cdef[2:])
                assert cdef[0] == "*"
                cdef = ['*', cdef[1:]]
            elif cdef[0][:3] == 'ck_':
                # ck_<name> * <varname>
                #ctype = aliases[cdef[0]]
                ctype = cdef[0]
                cdef = "".join(cdef[1:])
                if cdef[0] == "*":
                    cdef = ['*', cdef[1:]]
                else:
                    cdef = [cdef]
            elif cdef[0] == "void":
                # void * <varname>
                cdef = "".join(cdef[1:])
                assert cdef[0] == "*"
                cdef = [cdef[1:]]
                ctype = 'c_void_p'
            else:
                # [char|int|long] * <varname>
                t = {"char": 'c_char', "int": 'c_int', "long": 'c_long'}
                ctype = t[cdef[0]]
                cdef = cdef[1:]
        cdef = "".join(cdef)
        assert cdef != ''
        while cdef and cdef[0] == "*":
            cdef = cdef[1:]
            ctype = 'POINTER(%s)'%ctype
        args.append(ctype)
    print('# ck_rv_t CK_'+funcname, funcdef)
    print('CK_'+funcname, ' = CFUNCTYPE(%s)'%', '.join(args))

_CK_DECLARE_FUNCTION ('''C_Initialize, (void *init_args)''')
_CK_DECLARE_FUNCTION ('''C_Finalize, (void *reserved)''')
_CK_DECLARE_FUNCTION ('''C_GetInfo, (struct ck_info *info)''')
_CK_DECLARE_FUNCTION ('''C_GetFunctionList,
		      (struct ck_function_list **function_list)''')

_CK_DECLARE_FUNCTION ('''C_GetSlotList,
		      (unsigned char token_present, ck_slot_id_t *slot_list,
		       unsigned long *count)''')
_CK_DECLARE_FUNCTION ('''C_GetSlotInfo,
		      (ck_slot_id_t slot_id, struct ck_slot_info *info)''')
_CK_DECLARE_FUNCTION ('''C_GetTokenInfo,
		      (ck_slot_id_t slot_id, struct ck_token_info *info)''')
_CK_DECLARE_FUNCTION ('''C_WaitForSlotEvent,
		      (ck_flags_t flags, ck_slot_id_t *slot, void *reserved)''')
_CK_DECLARE_FUNCTION ('''C_GetMechanismList,
		      (ck_slot_id_t slot_id,
		       ck_mechanism_type_t *mechanism_list,
		       unsigned long *count)''')
_CK_DECLARE_FUNCTION ('''C_GetMechanismInfo,
		      (ck_slot_id_t slot_id, ck_mechanism_type_t type,
		       struct ck_mechanism_info *info)''')
_CK_DECLARE_FUNCTION ('''C_InitToken,
		      (ck_slot_id_t slot_id, unsigned char *pin,
		       unsigned long pin_len, unsigned char *label)''')
_CK_DECLARE_FUNCTION ('''C_InitPIN,
		      (ck_session_handle_t session, unsigned char *pin,
		       unsigned long pin_len)''')
_CK_DECLARE_FUNCTION ('''C_SetPIN,
		      (ck_session_handle_t session, unsigned char *old_pin,
		       unsigned long old_len, unsigned char *new_pin,
		       unsigned long new_len)''')

_CK_DECLARE_FUNCTION ('''C_OpenSession,
		      (ck_slot_id_t slot_id, ck_flags_t flags,
		       void *application, ck_notify_t notify,
		       ck_session_handle_t *session)''')
_CK_DECLARE_FUNCTION ('''C_CloseSession, (ck_session_handle_t session)''')
_CK_DECLARE_FUNCTION ('''C_CloseAllSessions, (ck_slot_id_t slot_id)''')
_CK_DECLARE_FUNCTION ('''C_GetSessionInfo,
		      (ck_session_handle_t session,
		       struct ck_session_info *info)''')
_CK_DECLARE_FUNCTION ('''C_GetOperationState,
		      (ck_session_handle_t session,
		       unsigned char *operation_state,
		       unsigned long *operation_state_len)''')
_CK_DECLARE_FUNCTION ('''C_SetOperationState,
		      (ck_session_handle_t session,
		       unsigned char *operation_state,
		       unsigned long operation_state_len,
		       ck_object_handle_t encryption_key,
		       ck_object_handle_t authentiation_key)''')
_CK_DECLARE_FUNCTION ('''C_Login,
		      (ck_session_handle_t session, ck_user_type_t user_type,
		       unsigned char *pin, unsigned long pin_len)''')
_CK_DECLARE_FUNCTION ('''C_Logout, (ck_session_handle_t session)''')

_CK_DECLARE_FUNCTION ('''C_CreateObject,
		      (ck_session_handle_t session,
		       struct ck_attribute *templ,
		       unsigned long count, ck_object_handle_t *object)''')
_CK_DECLARE_FUNCTION ('''C_CopyObject,
		      (ck_session_handle_t session, ck_object_handle_t object,
		       struct ck_attribute *templ, unsigned long count,
		       ck_object_handle_t *new_object)''')
_CK_DECLARE_FUNCTION ('''C_DestroyObject,
		      (ck_session_handle_t session,
		       ck_object_handle_t object)''')
_CK_DECLARE_FUNCTION ('''C_GetObjectSize,
		      (ck_session_handle_t session,
		       ck_object_handle_t object,
		       unsigned long *size)''')
_CK_DECLARE_FUNCTION ('''C_GetAttributeValue,
		      (ck_session_handle_t session,
		       ck_object_handle_t object,
		       struct ck_attribute *templ,
		       unsigned long count)''')
_CK_DECLARE_FUNCTION ('''C_SetAttributeValue,
		      (ck_session_handle_t session,
		       ck_object_handle_t object,
		       struct ck_attribute *templ,
		       unsigned long count)''')
_CK_DECLARE_FUNCTION ('''C_FindObjectsInit,
		      (ck_session_handle_t session,
		       struct ck_attribute *templ,
		       unsigned long count)''')
_CK_DECLARE_FUNCTION ('''C_FindObjects,
		      (ck_session_handle_t session,
		       ck_object_handle_t *object,
		       unsigned long max_object_count,
		       unsigned long *object_count)''')
_CK_DECLARE_FUNCTION ('''C_FindObjectsFinal,
		      (ck_session_handle_t session)''')

_CK_DECLARE_FUNCTION ('''C_EncryptInit,
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       ck_object_handle_t key)''')
_CK_DECLARE_FUNCTION ('''C_Encrypt,
		      (ck_session_handle_t session,
		       unsigned char *data, unsigned long data_len,
		       unsigned char *encrypted_data,
		       unsigned long *encrypted_data_len)''')
_CK_DECLARE_FUNCTION ('''C_EncryptUpdate,
		      (ck_session_handle_t session,
		       unsigned char *part, unsigned long part_len,
		       unsigned char *encrypted_part,
		       unsigned long *encrypted_part_len)''')
_CK_DECLARE_FUNCTION ('''C_EncryptFinal,
		      (ck_session_handle_t session,
		       unsigned char *last_encrypted_part,
		       unsigned long *last_encrypted_part_len)''')

_CK_DECLARE_FUNCTION ('''C_DecryptInit,
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       ck_object_handle_t key)''')
_CK_DECLARE_FUNCTION ('''C_Decrypt,
		      (ck_session_handle_t session,
		       unsigned char *encrypted_data,
		       unsigned long encrypted_data_len,
		       unsigned char *data, unsigned long *data_len)''')
_CK_DECLARE_FUNCTION ('''C_DecryptUpdate,
		      (ck_session_handle_t session,
		       unsigned char *encrypted_part,
		       unsigned long encrypted_part_len,
		       unsigned char *part, unsigned long *part_len)''')
_CK_DECLARE_FUNCTION ('''C_DecryptFinal,
		      (ck_session_handle_t session,
		       unsigned char *last_part,
		       unsigned long *last_part_len)''')

_CK_DECLARE_FUNCTION ('''C_DigestInit,
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism)''')
_CK_DECLARE_FUNCTION ('''C_Digest,
		      (ck_session_handle_t session,
		       unsigned char *data, unsigned long data_len,
		       unsigned char *digest,
		       unsigned long *digest_len)''')
_CK_DECLARE_FUNCTION ('''C_DigestUpdate,
		      (ck_session_handle_t session,
		       unsigned char *part, unsigned long part_len)''')
_CK_DECLARE_FUNCTION ('''C_DigestKey,
		      (ck_session_handle_t session, ck_object_handle_t key)''')
_CK_DECLARE_FUNCTION ('''C_DigestFinal,
		      (ck_session_handle_t session,
		       unsigned char *digest,
		       unsigned long *digest_len)''')

_CK_DECLARE_FUNCTION ('''C_SignInit,
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       ck_object_handle_t key)''')
_CK_DECLARE_FUNCTION ('''C_Sign,
		      (ck_session_handle_t session,
		       unsigned char *data, unsigned long data_len,
		       unsigned char *signature,
		       unsigned long *signature_len)''')
_CK_DECLARE_FUNCTION ('''C_SignUpdate,
		      (ck_session_handle_t session,
		       unsigned char *part, unsigned long part_len)''')
_CK_DECLARE_FUNCTION ('''C_SignFinal,
		      (ck_session_handle_t session,
		       unsigned char *signature,
		       unsigned long *signature_len)''')
_CK_DECLARE_FUNCTION ('''C_SignRecoverInit,
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       ck_object_handle_t key)''')
_CK_DECLARE_FUNCTION ('''C_SignRecover,
		      (ck_session_handle_t session,
		       unsigned char *data, unsigned long data_len,
		       unsigned char *signature,
		       unsigned long *signature_len)''')

_CK_DECLARE_FUNCTION ('''C_VerifyInit,
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       ck_object_handle_t key)''')
_CK_DECLARE_FUNCTION ('''C_Verify,
		      (ck_session_handle_t session,
		       unsigned char *data, unsigned long data_len,
		       unsigned char *signature,
		       unsigned long signature_len)''')
_CK_DECLARE_FUNCTION ('''C_VerifyUpdate,
		      (ck_session_handle_t session,
		       unsigned char *part, unsigned long part_len)''')
_CK_DECLARE_FUNCTION ('''C_VerifyFinal,
		      (ck_session_handle_t session,
		       unsigned char *signature,
		       unsigned long signature_len)''')
_CK_DECLARE_FUNCTION ('''C_VerifyRecoverInit,
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       ck_object_handle_t key)''')
_CK_DECLARE_FUNCTION ('''C_VerifyRecover,
		      (ck_session_handle_t session,
		       unsigned char *signature,
		       unsigned long signature_len,
		       unsigned char *data,
		       unsigned long *data_len)''')

_CK_DECLARE_FUNCTION ('''C_DigestEncryptUpdate,
		      (ck_session_handle_t session,
		       unsigned char *part, unsigned long part_len,
		       unsigned char *encrypted_part,
		       unsigned long *encrypted_part_len)''')
_CK_DECLARE_FUNCTION ('''C_DecryptDigestUpdate,
		      (ck_session_handle_t session,
		       unsigned char *encrypted_part,
		       unsigned long encrypted_part_len,
		       unsigned char *part,
		       unsigned long *part_len)''')
_CK_DECLARE_FUNCTION ('''C_SignEncryptUpdate,
		      (ck_session_handle_t session,
		       unsigned char *part, unsigned long part_len,
		       unsigned char *encrypted_part,
		       unsigned long *encrypted_part_len)''')
_CK_DECLARE_FUNCTION ('''C_DecryptVerifyUpdate,
		      (ck_session_handle_t session,
		       unsigned char *encrypted_part,
		       unsigned long encrypted_part_len,
		       unsigned char *part,
		       unsigned long *part_len)''')

_CK_DECLARE_FUNCTION ('''C_GenerateKey,
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       struct ck_attribute *templ,
		       unsigned long count,
		       ck_object_handle_t *key)''')
_CK_DECLARE_FUNCTION ('''C_GenerateKeyPair,
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       struct ck_attribute *public_key_template,
		       unsigned long public_key_attribute_count,
		       struct ck_attribute *private_key_template,
		       unsigned long private_key_attribute_count,
		       ck_object_handle_t *public_key,
		       ck_object_handle_t *private_key)''')
_CK_DECLARE_FUNCTION ('''C_WrapKey,
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       ck_object_handle_t wrapping_key,
		       ck_object_handle_t key,
		       unsigned char *wrapped_key,
		       unsigned long *wrapped_key_len)''')
_CK_DECLARE_FUNCTION ('''C_UnwrapKey,
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       ck_object_handle_t unwrapping_key,
		       unsigned char *wrapped_key,
		       unsigned long wrapped_key_len,
		       struct ck_attribute *templ,
		       unsigned long attribute_count,
		       ck_object_handle_t *key)''')
_CK_DECLARE_FUNCTION ('''C_DeriveKey,
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       ck_object_handle_t base_key,
		       struct ck_attribute *templ,
		       unsigned long attribute_count,
		       ck_object_handle_t *key)''')

_CK_DECLARE_FUNCTION ('''C_SeedRandom,
		      (ck_session_handle_t session, unsigned char *seed,
		       unsigned long seed_len)''')
_CK_DECLARE_FUNCTION ('''C_GenerateRandom,
		      (ck_session_handle_t session,
		       unsigned char *random_data,
		       unsigned long random_len)''')

_CK_DECLARE_FUNCTION ('''C_GetFunctionStatus, (ck_session_handle_t session)''')
_CK_DECLARE_FUNCTION ('''C_CancelFunction, (ck_session_handle_t session)''')
