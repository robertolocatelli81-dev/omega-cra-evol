"""0.13.2: on Windows the ledger takes msvcrt.locking, the equivalent of flock (until 0.13.1 every append there was
refused: «exclusive lock unavailable on this filesystem»). Played here with a stand-in msvcrt so it runs on every system;
the secret-leaks job runs the real one on windows-latest."""
import os
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from omega_cra_evol import ledger as L  # noqa: E402


class WindowsLock(unittest.TestCase):
    def fake(self, fail_times=0):
        calls = []
        m = types.ModuleType("msvcrt")
        m.LK_NBLCK = 2
        state = {"left": fail_times}

        def locking(fd, mode, n):
            calls.append((os.lseek(fd, 0, os.SEEK_CUR), mode, n))
            if state["left"]:
                state["left"] -= 1
                raise OSError(36, "locked")
        m.locking = locking
        return m, calls

    def append_with(self, m):
        t = tempfile.TemporaryDirectory(prefix="crawin-")
        self.addCleanup(t.cleanup)
        with mock.patch.object(L.os, "name", "nt"), mock.patch.dict(sys.modules, {"msvcrt": m}):
            return L.Ledger(os.path.join(t.name, "l.jsonl")).append({"k": 1})

    def test_the_lock_is_taken_and_the_record_written(self):
        m, calls = self.fake()
        e = self.append_with(m)
        self.assertEqual(e["idx"], 0)
        self.assertEqual(calls, [(L._WIN_LOCK_AT, m.LK_NBLCK, 1)])

    def test_a_busy_lock_is_waited_for(self):
        m, calls = self.fake(fail_times=3)
        self.append_with(m)
        self.assertEqual(len(calls), 4)

    def test_no_msvcrt_is_still_refused(self):
        with mock.patch.object(L.os, "name", "nt"), mock.patch.dict(sys.modules, {"msvcrt": None}):
            with tempfile.TemporaryDirectory() as d, self.assertRaises(RuntimeError):
                L.Ledger(os.path.join(d, "l.jsonl")).append({"k": 1})


if __name__ == "__main__":
    unittest.main()
