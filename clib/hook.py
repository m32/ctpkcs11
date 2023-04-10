import ctypes


class Hook:
    def __init__(self):
        dll = ctypes.cdll.LoadLibrary("./libfunchook.so")
        self.create = ctypes.CFUNCTYPE(ctypes.c_void_p)(("funchook_create", dll))
        self.prepare = ctypes.CFUNCTYPE(
            ctypes.c_ssize_t, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p
        )(("funchook_prepare", dll))
        self.install = ctypes.CFUNCTYPE(
            ctypes.c_ssize_t, ctypes.c_void_p, ctypes.c_int
        )(("funchook_install", dll))
        self.uninstall = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_int)(
            ("funchook_uninstall", dll)
        )
        self.destroy = ctypes.CFUNCTYPE(ctypes.c_void_p)(("funchook_destroy", dll))
        self.error_message = ctypes.CFUNCTYPE(ctypes.c_void_p)(
            ("funchook_error_message", dll)
        )
        self.set_debug_file = ctypes.CFUNCTYPE(ctypes.c_char_p)(
            ("funchook_set_debug_file", dll)
        )
        self.dll = dll


def main():
    PySys_WriteStdout = ctypes.pythonapi.PySys_WriteStdout
    PySys_WriteStdout.restype = None
    PySys_WriteStdout.argtypes = [ctypes.c_char_p]

    # must keep those references alive, or stuff will be GC'd and weird errors will occur
    # orig_write, hook, orig_write_ptr

    # create hook (this function will replace the original function)
    hook_type = ctypes.PYFUNCTYPE(None, ctypes.c_char_p)
    orig_write = None

    def hook_impl(msg):
        print("about to write: " + str(msg))  # do what we want
        orig_write(msg)  # call the original function

    hdll = Hook()
    hook = hook_type(hook_impl)

    fh = hdll.create()
    # create a pointer object with the function address
    orig_write_ptr = ctypes.c_void_p(
        ctypes.c_void_p.from_address(ctypes.addressof(PySys_WriteStdout)).value
    )
    # orig_write_ptr.value will get a ptr to the original PySys_WriteStdout and PySys_WriteStdout will now point to the hook
    ret = hdll.prepare(fh, ctypes.addressof(orig_write_ptr), hook)
    assert not ret, "ret is " + str(ret)
    ret = hdll.install(fh, 0)
    assert not ret, "ret is " + str(ret)
    orig_write = hook_type.from_address(ctypes.addressof(orig_write_ptr))
    PySys_WriteStdout(b"hi there\n")

    hdll.uninstall(fh)
    hdll.destroy(fh)
    del hdll

if __name__ == "__main__":
    main()
