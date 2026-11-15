"""An append parses only the lines added since the last append, and behaves exactly as a full read (15/11/2026).

Generative: random sequences of appends and of changes made to the ledger or to the state file by someone else (a byte
changed in the middle, a truncation, garbage or blank lines, valid chained lines written by another tool, the state file
removed, malformed, of another version, or naming a wrong digest). After each step the same append is run on a copy
without the state file (the full read of before), and both must give the same bytes, the same entry and the same error.
Positive control: with the SHA-256 check of the state removed, the same generator finds a difference."""
import json
import os
import random
import shutil
import tempfile
import unittest
from unittest import mock

from omega_cra_evol import ledger as L

TS = "2026-11-15T12:00:00Z"


def outcome(path, data):
    try:
        e = L.Ledger(path).append(data, ts=TS)
        res = ("ok", json.dumps(e, sort_keys=True))
    except Exception as e:   # the type and the message must agree
        res = ("error", type(e).__name__, str(e).replace(path, "<ledger>"))
    with open(path, "rb") as f:
        return res, f.read()


def chained_line(prev_entries, data):
    idx = len(prev_entries)
    prev = prev_entries[-1]["self_hash"] if prev_entries else L.GENESIS
    e = {"idx": idx, "ts": TS, "prev_hash": prev, "data": data}
    e["self_hash"] = L.entry_hash(e)
    return e, L.canonical_bytes(e) + b"\n"


def mutate(rnd, path):
    """One change made outside the writer; returns its name."""
    state = path + L.STATE_SUFFIX
    raw = open(path, "rb").read() if os.path.exists(path) else b""
    k = rnd.randrange(11)
    if k == 0 and raw:
        i = rnd.randrange(len(raw)); b = bytearray(raw); b[i] ^= 1 << rnd.randrange(7)
        open(path, "wb").write(bytes(b)); return "byte"
    if k == 1 and raw:
        open(path, "wb").write(raw[:rnd.randrange(len(raw))]); return "truncate"
    if k == 2:
        open(path, "ab").write(rnd.choice([b"not json\n", b"{\"x\":1}\n", b"[1,2]\n", b"{\"self_hash\":\"zz\"}\n"])); return "garbage"
    if k == 3:
        open(path, "ab").write(rnd.choice([b"\n", b"   \n", b"\t\n"])); return "blank"
    if k == 4:
        ents = []
        for line in raw.splitlines():
            try:
                ents.append(json.loads(line))
            except ValueError:
                pass
        if ents and all(isinstance(x, dict) and "self_hash" in x for x in ents):
            _, line = chained_line(ents, {"other": rnd.randrange(100)})
            open(path, "ab").write(line); return "other_writer"
        return "none"
    if k == 5 and os.path.exists(state):
        os.remove(state); return "state_removed"
    if k == 6 and os.path.exists(state):
        open(state, "wb").write(rnd.choice([b"", b"{", b"[]", b"\xff\xfe", b"{}" * 3000])); return "state_garbage"
    s = None
    if os.path.exists(state):
        try:
            s = json.loads(open(state, "rb").read())
        except ValueError:
            s = None
    if not isinstance(s, dict):
        s = None
    if k == 7 and s is not None:
        s[rnd.choice(["version", "extra"])] = 2; json.dump(s, open(state, "w")); return "state_other"
    if k == 8 and s is not None:
        s["sha256"] = "%064x" % rnd.getrandbits(256); json.dump(s, open(state, "w")); return "state_wrong_digest"
    if k == 9 and s is not None:
        s[rnd.choice(["n", "size", "lines"])] = rnd.choice([-1, True, "3", 10**12]); json.dump(s, open(state, "w")); return "state_bad_field"
    if k == 10 and raw and os.path.exists(state):   # same size, other content
        b = bytearray(raw); b[len(raw) // 2] ^= 2; open(path, "wb").write(bytes(b)); return "same_size_change"
    return "none"


def run_generator(seed, steps):
    rnd = random.Random(seed)
    d = tempfile.mkdtemp()
    fast, ref = os.path.join(d, "fast.jsonl"), os.path.join(d, "ref.jsonl")
    diffs, kinds = [], set()
    try:
        for step in range(steps):
            if step and rnd.random() < 0.35:
                kinds.add(mutate(rnd, fast))
                for suffix in ("",):
                    shutil.copyfile(fast + suffix, ref + suffix) if os.path.exists(fast) else None
            else:
                if os.path.exists(fast):
                    shutil.copyfile(fast, ref)
            if os.path.exists(ref + L.STATE_SUFFIX):
                os.remove(ref + L.STATE_SUFFIX)                  # the reference always reads the whole ledger
            data = {"step": step, "v": rnd.randrange(1000)}
            a, b = outcome(fast, data), outcome(ref, data)
            if a != b:
                diffs.append((step, a[0], b[0]))
    finally:
        shutil.rmtree(d)
    return diffs, kinds


class TestAppendState(unittest.TestCase):
    def test_generated_sequences_match_the_full_read(self):
        all_kinds = set()
        for seed in range(40):
            diffs, kinds = run_generator(seed, 60)
            self.assertEqual(diffs, [], f"seed {seed}")
            all_kinds |= kinds
        # every kind of change was exercised
        self.assertTrue({"byte", "truncate", "garbage", "blank", "other_writer", "state_removed", "state_garbage",
                         "state_other", "state_wrong_digest", "state_bad_field", "same_size_change"} <= all_kinds, all_kinds)

    def test_positive_control_without_the_digest_check(self):
        real = L._prefix_sha256
        def trusting(f, size):        # a broken writer that believes the state file without hashing the file
            try:
                with open(f.name + L.STATE_SUFFIX, "rb") as g:
                    s = json.loads(g.read())
            except (OSError, ValueError):
                return real(f, size)
            return s["sha256"] if isinstance(s, dict) and s.get("size") == size else real(f, size)
        d = tempfile.mkdtemp(); p = os.path.join(d, "l.jsonl")
        try:
            for i in range(3):
                L.Ledger(p).append({"i": i}, ts=TS)
            raw = open(p, "rb").read(); second = raw.index(b"\n") + 1
            open(p, "wb").write(raw[:second] + b"x" + raw[second + 1:])     # line 2 unparsable, same size
            with self.assertRaisesRegex(ValueError, "line 2 unparsable"):
                L.Ledger(p).append({"i": 3}, ts=TS)                          # the real writer sees it
            with mock.patch.object(L, "_prefix_sha256", trusting):
                L.Ledger(p).append({"i": 3}, ts=TS)                          # the trusting one does not
        finally:
            shutil.rmtree(d)
        found = 0
        with mock.patch.object(L, "_prefix_sha256", trusting):
            for seed in range(40):
                found += len(run_generator(seed, 60)[0])
        self.assertGreater(found, 0)

    def test_only_new_lines_are_parsed(self):
        d = tempfile.mkdtemp(); p = os.path.join(d, "l.jsonl")
        try:
            lg = L.Ledger(p)
            for i in range(200):
                lg.append({"i": i}, ts=TS)
            with mock.patch.object(L, "parse_line", wraps=L.parse_line) as pl:
                lg.append({"i": "next"}, ts=TS)
                self.assertEqual(pl.call_count, 0)     # nothing re-parsed: 201 lines are behind the checked digest
                os.remove(p + L.STATE_SUFFIX)
                lg.append({"i": "after"}, ts=TS)
                self.assertEqual(pl.call_count, 201)   # no state: the 201 lines are read, as before
            v = L.Ledger(p).verify(); self.assertTrue(v["chain_ok"], v); self.assertEqual(v["entries"], 202)
        finally:
            shutil.rmtree(d)

    def test_the_state_file_is_not_written_into_the_chain_and_never_read_by_verify(self):
        d = tempfile.mkdtemp(); p = os.path.join(d, "l.jsonl")
        try:
            lg = L.Ledger(p); lg.append({"a": 1}, ts=TS); lg.append({"a": 2}, ts=TS)
            with open(p + L.STATE_SUFFIX, "wb") as f:
                f.write(b"garbage")
            v1 = L.Ledger(p).verify()
            os.remove(p + L.STATE_SUFFIX)
            self.assertEqual(L.Ledger(p).verify(), v1)
        finally:
            shutil.rmtree(d)


if __name__ == "__main__":
    unittest.main()
