import base64
import os
import tempfile
import unittest

from uvpn.__main__ import load_psk


class LoadPskTest(unittest.TestCase):
    def write(self, data: bytes) -> str:
        fd, path = tempfile.mkstemp()
        os.write(fd, data)
        os.close(fd)
        os.chmod(path, 0o600)
        self.addCleanup(os.unlink, path)
        return path

    def test_windows_copy_paste_accepted(self):
        key = os.urandom(32)
        b64 = base64.b64encode(key)
        # BOM, CRLF and a key wrapped over two lines, as Notepad or a chat app may save it.
        path = self.write(b"\xef\xbb\xbf" + b64[:20] + b"\r\n" + b64[20:] + b"\r\n")
        self.assertEqual(load_psk(path), key)

    def test_garbage_gives_clear_error(self):
        path = self.write(b"not a key!\n")
        with self.assertRaises(SystemExit) as ctx:
            load_psk(path)
        self.assertIn("not a valid key", str(ctx.exception))

    def test_wrong_length_rejected(self):
        path = self.write(base64.b64encode(os.urandom(16)) + b"\n")
        with self.assertRaises(SystemExit):
            load_psk(path)


if __name__ == "__main__":
    unittest.main()
