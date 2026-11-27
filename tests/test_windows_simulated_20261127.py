"""0.13.2 (final review): the lines that run only on Windows, played on every system with os.name, msvcrt and the
kernel32 call stood in for — on Linux and macOS they had no test (mutants of each survived there; the real ones run in
the Windows jobs of the CI)."""
import errno
import os
import sys
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import importlib  # noqa: E402
from omega_cra_evol import cli, ledger as L  # noqa: E402
V = importlib.import_module("omega_cra_evol.verify_pack")


def windows(file_type=3):
    """os.name 'nt', msvcrt.get_osfhandle and kernel32.GetFileType stood in for (3 = FILE_TYPE_PIPE, 1 = a disk file)."""
    import ctypes
    ms = types.ModuleType("msvcrt"); ms.get_osfhandle = lambda fd: 7
    k32 = types.SimpleNamespace(GetFileType=lambda h: file_type)
    return [mock.patch.object(cli.os, "name", "nt"), mock.patch.dict(sys.modules, {"msvcrt": ms}),
            mock.patch.object(ctypes, "windll", types.SimpleNamespace(kernel32=k32), create=True)]


class Patched:
    def __init__(self, patches): self.p = patches
    def __enter__(self): [p.start() for p in self.p]
    def __exit__(self, *a): [p.stop() for p in reversed(self.p)]


class FakeBuf:
    """a full PIPE_NOWAIT pipe as Python before 3.12 reports it: OSError ENOSPC `full` times, nothing taken."""
    def __init__(self, full=0, overcount=False):
        self.got, self.sizes, self.full, self.overcount = bytearray(), [], full, overcount
    def write(self, b):
        self.sizes.append(len(b))
        if self.full:
            self.full -= 1
            raise OSError(errno.ENOSPC, "No space left on device")
        self.got += bytes(b)
        extra, self.overcount = (1000 if self.overcount else 0), False   # once: more than the piece, less than the rest
        return len(b) + extra
    def flush(self): pass
    def fileno(self): return 1
    def seekable(self): return False


class FakeOut:
    encoding, errors = "cp1252", "strict"
    def __init__(self, buf): self.buffer = buf
    def flush(self): pass


class FullPipeError(unittest.TestCase):
    def test_enospc_only_on_a_pipe_only_on_windows(self):
        b = FakeBuf()
        with Patched(windows(3)):
            self.assertTrue(cli._full_pipe_error(OSError(errno.ENOSPC, "x"), b))
            self.assertFalse(cli._full_pipe_error(OSError(errno.EINVAL, "x"), b))     # another errno stays an error
            self.assertFalse(cli._full_pipe_error(BlockingIOError(errno.ENOSPC, "x"), b))
        with Patched(windows(1)):                                                      # a full DISK stays the error it is
            self.assertFalse(cli._full_pipe_error(OSError(errno.ENOSPC, "x"), b))
        with mock.patch.object(cli.os, "name", "posix"):
            self.assertFalse(cli._full_pipe_error(OSError(errno.ENOSPC, "x"), b))


class WriteAllOnWindowsBefore312(unittest.TestCase):
    def run_with(self, buf, text):
        sleeps = []
        with Patched(windows(3) + [mock.patch.object(cli.sys, "stdout", FakeOut(buf)),
                                   mock.patch.dict(os.environ, {}, clear=False)]), \
                mock.patch("time.sleep", lambda s: sleeps.append(s)):
            os.environ.pop("PYTHONIOENCODING", None)
            cli._write_all(text)
        return sleeps

    def test_waited_for_and_written_in_pieces_of_4096(self):
        text = "x" * 20000 + "✓\n"
        buf = FakeBuf(full=3)
        sleeps = self.run_with(buf, text)
        self.assertEqual(bytes(buf.got), text.replace("\n", os.linesep).encode("utf-8"))   # whole, once, UTF-8
        self.assertLessEqual(max(buf.sizes), 4096)
        self.assertEqual(sleeps, [0.01] * 3)                                                  # one 10 ms wait per ENOSPC

    def test_a_count_above_the_piece_is_a_short_write(self):
        with self.assertRaises(OSError):
            self.run_with(FakeBuf(overcount=True), "x" * 20000)


class ReceiptEncoding(unittest.TestCase):
    def test_utf8_unless_pythonioencoding(self):
        out = FakeOut(FakeBuf())
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("PYTHONIOENCODING", None)
            self.assertEqual(cli._text_layer_bytes(out, out.buffer, "ö"), "ö".encode("utf-8"))
        with mock.patch.dict(os.environ, {"PYTHONIOENCODING": "cp1252"}):
            self.assertEqual(cli._text_layer_bytes(out, out.buffer, "ö"), b"\xf6")


class LedgerLockGivesUp(unittest.TestCase):
    def test_a_lock_never_released_is_a_refusal_after_the_deadline(self):
        import tempfile
        calls, now = [], [0.0]
        ms = types.ModuleType("msvcrt"); ms.LK_NBLCK = 2
        def locking(fd, mode, n):
            calls.append(1)
            if len(calls) > 10000:
                raise AssertionError("never gives up")
            raise OSError(36, "locked")
        ms.locking = locking
        def mono():
            now[0] += 1.0
            return now[0]
        with tempfile.TemporaryDirectory() as d, mock.patch.object(L.os, "name", "nt"), \
                mock.patch.dict(sys.modules, {"msvcrt": ms}), mock.patch.object(L.time, "monotonic", mono), \
                mock.patch.object(L.time, "sleep", lambda s: None):
            with self.assertRaises(RuntimeError):
                L.Ledger(os.path.join(d, "l.jsonl")).append({"k": 1})
            self.assertLess(len(calls), 100)


class PackPathNamesAFolder(unittest.TestCase):
    def test_separators_of_each_system(self):
        with mock.patch.object(V.os, "name", "nt"):
            for p in ("p.json/", "p.json/.", "p.json\\", "p.json\\.", b"p.json\\"):
                self.assertTrue(V._names_a_folder(p), p)
            for p in ("p.json", "d\\p.json", "p.json.", "d/.p.json"):
                self.assertFalse(V._names_a_folder(p), p)
        with mock.patch.object(V.os, "name", "posix"):
            self.assertTrue(V._names_a_folder("p.json/."))
            self.assertFalse(V._names_a_folder("p.json\\"))   # a name character there


if __name__ == "__main__":
    unittest.main()
