#!/usr/bin/env vpython3
if __name__ == '__main__':
    import run
from tconfig import TestCase, api, HSMError


# SHA1 of "abc"
SHA1_abc = bytes(
    (
        0xA9,
        0x99,
        0x3E,
        0x36,
        0x47,
        0x6,
        0x81,
        0x6A,
        0xBA,
        0x3E,
        0x25,
        0x71,
        0x78,
        0x50,
        0xC2,
        0x6C,
        0x9C,
        0xD0,
        0xD8,
        0x9D,
    )
)


class TestUtil(TestCase):
    withlogin = False

    def test_digest(self):
        digest = self.session.digest(b"abc")
        self.assertSequenceEqual(digest, SHA1_abc)

    def test_digestSession(self):
        digestSession = self.session.digestSession()
        digestSession.update(b"abc")
        digest = digestSession.final()
        self.assertSequenceEqual(digest, SHA1_abc)



if __name__ == '__main__':
    import unittest
    unittest.main()
