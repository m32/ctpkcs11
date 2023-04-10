import os
import sys
import shutil

sys.path.insert(1, '..')

class Config:
    def __init__(self, top=None):
        self.top = top or os.getcwd()
        self.dllpath = None
        self.label = ''
        self.pin = ''

    def SoftHSMInit(self):
        conf = os.environ["SOFTHSM2_CONF"] = os.path.join(self.top, "softhsm2.conf")
        if not os.path.exists(conf):
            open(conf, "wt").write(
        """\
log.level = DEBUG
directories.tokendir = %s/softhsm2/
objectstore.backend = file
slots.removable = false
"""
            % self.top
        )
        if not os.path.exists(os.path.join(self.top, "softhsm2")):
            os.mkdir(os.path.join(self.top, "softhsm2"))
        if sys.platform == "win32":
            self.dllpath = r"W:\binw\SoftHSM2\lib\softhsm2-x64.dll"
        else:
            self.dllpath = "/usr/lib/softhsm/libsofthsm2.so"

    def SoftHSMCleanup(self):
        def unlink(fqname):
            if os.path.exists(fqname):
                os.unlink(fqname)
        unlink(os.path.join(self.top, "softhsm2.conf"))
        unlink(os.path.join(self.top, "cert-hsm-ca.der"))
        unlink(os.path.join(self.top, "cert-hsm-ca.pem"))
        unlink(os.path.join(self.top, "cert-hsm-user1.der"))
        unlink(os.path.join(self.top, "cert-hsm-user1.pem"))
        shutil.rmtree(os.path.join(self.top, "softhsm2"), ignore_errors=True)
        self.label = ''
        self.pin = ''

    def endesive(self):
        self.label = 'endesieve'
        self.pin = 'secret1'

    def Certum(self):
        import ctypes as ct
        if sys.platform == "win32":
            self.dllpath = r"c:\windows\system32\cryptoCertum3PKCS.dll"
        else:
            self.openssl_1_1 = [
                #ct.CDLL('/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1', ct.RTLD_GLOBAL),
                ct.CDLL('/usr/lib/x86_64-linux-gnu/libssl.so.1.1', ct.RTLD_GLOBAL),
            ]
            self.dllpath = '/devel/bin/proCertumSmartSign/libcryptoCertum3PKCS.so'
            self.dllpath = "/devel/bin/proCertumSmartSign/libcrypto3PKCS.so"
        self.label = 'certum'
        self.pin = "1234"
