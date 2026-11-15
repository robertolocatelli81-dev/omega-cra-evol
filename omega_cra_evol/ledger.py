# SPDX-License-Identifier: AGPL-3.0-or-later
"""Append-only hash-chained JSONL ledger in the cryptovalid profile.

Entry: {"idx": n, "ts": "YYYY-MM-DDTHH:MM:SSZ", "prev_hash": <64 hex>, "data": {...}, "self_hash": <64 hex>} where
self_hash = SHA-256 of the canonical JSON of the entry without self_hash, and genesis prev_hash = 64 zeros.
Because the profile is the same, an evidence ledger written here is verified by the independent cryptovalid
checkers (verifier.py, cvverify.mjs, Go cvverify, Rust) and by cryptovalid's signed chain tip.

Writer discipline (lessons paid for on 15/09/2026, in the open): one descriptor, exclusive flock BEFORE reading the
tail, write under the same lock (two processes reading the tail outside the lock forked the chain); a last line
that is complete but lost its newline is closed before the next record (never two records on one line); a tail
that does not parse is never continued from (refused, recovery is a human decision); an empty ledger is FAIL
(nothing verified), never a third verdict.
"""
from __future__ import annotations

# The names other code may import from this module (provisional tier of API.md: typed, may change in a minor
# release with a changelog note). Everything else here is private. tests/test_api_surface.py keeps the list.
__all__ = [
    "FileTooLarge", "GENESIS", "Ledger", "MAX_DOC_BYTES", "MAX_LINE_BYTES", "NotRegularFile", "UnreadableFile",
    "entry_hash", "is_blank_line", "line_content", "load_trust_store", "open_regular", "parse_line",
    "read_regular",
]

import json
import logging
import os
import stat
from datetime import datetime, timezone
from typing import Any, BinaryIO, Dict, Iterator, List, Optional, Tuple

from .canonical import MAX_DEPTH, canonical_bytes, deep_recursion, nesting_depth, sha256_hex

GENESIS = "0" * 64
_log = logging.getLogger("omega_cra_evol.ledger")


def _now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _lock(f) -> bool:
    try:
        import fcntl
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        return True
    except (ImportError, OSError) as e:  # non-POSIX or a filesystem without flock: SAY it
        _log.warning("ledger: no exclusive lock on %s (%s): concurrent appends are not serialised", getattr(f, "name", "?"), e)
        return False


def _refuse_constant(name: str):
    raise ValueError(f"non-JSON constant {name} in ledger line")


MAX_LINE_BYTES = 64 << 20   # same bound as cryptovalid's Go verifier (MaxLineBytes): the four cra verifiers agree on it
# ONE bound for every JSON document a verifier reads — a ledger line, the pack, the signature sidecar, the signed tip, the
# trust store: the four verifiers refuse a larger one unread (the ledger as a whole is bounded per line, not in total).
MAX_DOC_BYTES = MAX_LINE_BYTES


class UnreadableFile(OSError):
    """The path opened but is not something a verifier may read: not a regular file, or above the size bound."""


class NotRegularFile(UnreadableFile):
    def __init__(self) -> None:
        super().__init__("not a regular file")


class FileTooLarge(UnreadableFile):
    def __init__(self, cap: int) -> None:
        super().__init__(f"larger than {cap} bytes")


_OPEN_FLAGS = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOCTTY", 0) | getattr(os, "O_CLOEXEC", 0)


def open_regular(path: str) -> BinaryIO:
    """Open for reading WITHOUT blocking (a FIFO with no writer, a device) and keep the descriptor only if it is a
    regular file — decided on the open descriptor (fstat), so the check and the read see the same object. A FIFO,
    /dev/zero (directly or through a symlink), a socket or a directory raise NotRegularFile before any byte is read.
    Measured 25/09/2026: a FIFO in place of the pack, sidecar, tip or trust store blocked every verifier, and a symlink
    to /dev/zero read until the process was killed for memory. A path that is not a regular file is refused BEFORE it is
    opened (opening a device can act on it); the fstat on the open descriptor closes the race with a swap in between."""
    if not stat.S_ISREG(os.stat(path).st_mode):
        raise NotRegularFile()
    fd = os.open(path, _OPEN_FLAGS)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise NotRegularFile()
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def read_regular(path: str, cap: int = MAX_DOC_BYTES) -> bytes:
    """The bytes of a regular file of at most `cap` bytes (FileTooLarge above it: refused on the size fstat reports,
    and again if more than `cap` bytes can be read — a file that grows while it is read is never buffered past the cap)."""
    with open_regular(path) as f:
        if os.fstat(f.fileno()).st_size > cap:
            raise FileTooLarge(cap)
        data = f.read(cap + 1)
    if len(data) > cap:
        raise FileTooLarge(cap)
    return data


def _no_dup_keys(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError(f"duplicate key {k!r} in ledger line (the profile forbids it: readers disagree on which wins)")
        d[k] = v
    return d


def line_content(raw: bytes) -> bytes:
    """One JSONL line without its terminator: exactly one trailing \\n, then at most one \\r (the same rule in the four
    verifiers — a run of \\r bytes is content, not a terminator, and counts against the bound)."""
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    if raw.endswith(b"\r"):
        raw = raw[:-1]
    return raw


def is_blank_line(content: bytes) -> bool:
    """Blank = only ASCII space / tab. Unicode spaces (U+00A0, U+2028, U+0085, U+FEFF…) are NOT blank: they are an
    unparsable line, in all four verifiers."""
    return content.strip(b" \t") == b""


def _refuse_int(tok: str):
    n = int(tok)
    if abs(n) > 2 ** 53 - 1:
        raise ValueError(f"integer {tok} outside ±(2^53-1) (the profile forbids it: a JavaScript reader would round it)")
    return n


def _refuse_float(tok: str):
    raise ValueError(f"floating-point number {tok} (the profile forbids floats: `10.0` and `10` would hash alike in one reader and not in another)")


def parse_line(line: str, allow_floats: bool = False) -> Any:
    """The profile's strict JSON: no NaN/Infinity, no duplicate keys, no floats (not even integral ones such as 10.0 —
    JSON.parse would silently turn them into 10), no integer outside ±(2^53-1). allow_floats=True only for third-party
    generator documents, which are stored as bytes, never canonicalised (numbers are then read as JSON allows)."""
    if nesting_depth(line) > MAX_DEPTH:       # linear pre-scan, before the recursive parser: exactly the verifiers' bound
        raise ValueError(f"json_too_deep: nesting exceeds the acceptance-profile bound {MAX_DEPTH}")
    try:
        with deep_recursion():                 # depth ≤ 512 must PARSE in the reference too (hooks cost frames per level)
            v = json.loads(line, parse_constant=_refuse_constant, object_pairs_hook=_no_dup_keys,
                           parse_float=(float if allow_floats else _refuse_float), parse_int=(int if allow_floats else _refuse_int))
    except RecursionError:
        raise ValueError("json_too_deep: the parser could not hold this nesting") from None
    if _has_lone_surrogate(v):   # for generator documents too: such a string could never be indexed or canonicalised
        raise ValueError("lone surrogate in a JSON string (the profile forbids it: it has no UTF-8 encoding)")
    return v


def _has_lone_surrogate(v) -> bool:
    """Iterative walk (a 512-deep document must not cost interpreter frames here)."""
    stack = [v]
    while stack:
        x = stack.pop()
        if isinstance(x, str):
            if any(0xD800 <= ord(c) <= 0xDFFF for c in x):
                return True
        elif isinstance(x, dict):
            stack.extend(x.keys())
            stack.extend(x.values())
        elif isinstance(x, list):
            stack.extend(x)
    return False


def load_trust_store(text: str) -> Dict[str, str]:
    """{signer_id: public_key_hex}: strict JSON, an object, string values — anything else is unreadable (exit 2 in
    every verifier), never a partial trust store."""
    try:
        d = parse_line(text)
    except (ValueError, RecursionError) as e:
        raise ValueError(f"trust store unreadable: {str(e)[:100]}") from None
    if not isinstance(d, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in d.items()):
        raise ValueError("trust store unreadable: must be a JSON object of signer_id -> public_key_hex strings")
    return d


def entry_hash(entry: Dict[str, Any]) -> str:
    return sha256_hex({k: v for k, v in entry.items() if k != "self_hash"})


def _tail_state(f, start: Optional[Dict[str, Any]] = None) -> Tuple[int, str, str, bool, int]:
    """(next idx, last self_hash, first self_hash, file ends without newline, lines read). Fail-closed on a bad line.
    `start` (from _cached_start) resumes after bytes already read by an earlier append and found unchanged."""
    if start is None:
        f.seek(0)
        n, last, first, unterminated, lineno = 0, GENESIS, GENESIS, False, 0
    else:
        f.seek(start["size"])
        n, last, first, unterminated, lineno = start["n"], start["last"], start["first"], False, start["lines"]
    while True:                                           # the writer reads with the VERIFIERS' rules: bounded, one terminator, ASCII blank
        raw = f.readline(MAX_LINE_BYTES + 2)
        if not raw:
            break
        lineno += 1
        if not raw.endswith(b"\n") and len(raw) == MAX_LINE_BYTES + 2:
            raise ValueError(f"ledger line {lineno} exceeds {MAX_LINE_BYTES} bytes: chain not continuable — verify, repair, record the incident")
        unterminated = not raw.endswith(b"\n")
        line = line_content(raw)
        if len(line) > MAX_LINE_BYTES:
            raise ValueError(f"ledger line {lineno} exceeds {MAX_LINE_BYTES} bytes: chain not continuable — verify, repair, record the incident")
        if is_blank_line(line):
            continue
        try:
            e = parse_line(line.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, RecursionError) as e:
            raise ValueError(f"ledger line {lineno} unparsable ({type(e).__name__}): chain not continuable — verify, repair, record the incident")
        if not isinstance(e, dict) or not isinstance(e.get("self_hash"), str) or len(e["self_hash"]) != 64:
            raise ValueError(f"ledger line {lineno} is not a chained entry")
        n += 1
        last = e["self_hash"]
        if n == 1:
            first = last
    return n, last, first, unterminated, lineno


# ── Append without re-reading the whole ledger (15/11/2026) ───────────────────────────────────────────────────────────
# Each append used to parse every line (O(n): 1.1 s per append at 10 000 entries, 23.7 s at 200 000, measured by
# Athena's review). After an append the writer keeps, next to the ledger, the size of the file, the SHA-256 of its
# bytes, and the chain state at its end. The next append hashes those bytes again (C speed) and, only if they are
# unchanged byte for byte, parses just the lines added since; any difference — a changed, removed or added byte in the
# part already read, a smaller file, a state file that is missing, malformed or of another version — means the whole
# ledger is read as before, with the same refusals. The state file is a cache, never evidence: nothing reads it but
# the writer, a verifier never sees it, and losing it only costs one full read.
STATE_SUFFIX = ".append-state.json"
STATE_VERSION = 1
_HASH_CHUNK = 1 << 20


def _prefix_sha256(f: BinaryIO, size: int) -> Optional[str]:
    import hashlib
    h, left = hashlib.sha256(), size
    f.seek(0)
    while left:
        b = f.read(min(_HASH_CHUNK, left))
        if not b:
            return None
        h.update(b); left -= len(b)
    return h.hexdigest()


def _cached_start(path: str, f: BinaryIO) -> Optional[Dict[str, Any]]:
    """The chain state at the end of the bytes the last append left, if those bytes are still the file's first bytes."""
    try:
        with open(path + STATE_SUFFIX, "rb") as g:
            raw = g.read(4096 + 1)
        s = json.loads(raw.decode("utf-8")) if len(raw) <= 4096 else None
    except (OSError, ValueError):
        return None
    keys = {"version", "size", "sha256", "n", "lines", "last", "first"}
    if not isinstance(s, dict) or set(s) != keys or s["version"] != STATE_VERSION:
        return None
    for k in ("size", "n", "lines"):
        if type(s[k]) is not int or s[k] < 0:
            return None
    for k in ("sha256", "last", "first"):
        if not isinstance(s[k], str) or len(s[k]) != 64 or any(c not in "0123456789abcdef" for c in s[k]):
            return None
    if os.fstat(f.fileno()).st_size < s["size"] or _prefix_sha256(f, s["size"]) != s["sha256"]:
        return None
    # NEMESIS 15/11/2026: the hash proves the bytes, not the chain state written beside it. A state file with the right
    # hash and another `last` or `n` made the writer append an entry that breaks the chain for good (prev_hash and idx
    # taken from the state file). The state is used only if the file's own first and last entries say the same.
    if s["n"] < 1 or _entry_at(f, 0, s["size"]) != (0, s["first"]) or _last_entry(f, s["size"]) != (s["n"] - 1, s["last"]):
        return None
    return s


def _entry_at(f: BinaryIO, start: int, size: int) -> Optional[Tuple[int, str]]:
    """(idx, self_hash) of the entry on the line that begins at `start`, within the first `size` bytes; None otherwise."""
    f.seek(start)
    raw = f.readline(min(MAX_LINE_BYTES + 2, max(size - start, 0)))
    if not raw.endswith(b"\n"):
        return None
    line = line_content(raw)
    if is_blank_line(line) or len(line) > MAX_LINE_BYTES:
        return None
    try:
        e = parse_line(line.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None
    if not isinstance(e, dict) or type(e.get("idx")) is not int or not isinstance(e.get("self_hash"), str):
        return None
    return e["idx"], e["self_hash"]


def _last_entry(f: BinaryIO, size: int) -> Optional[Tuple[int, str]]:
    """(idx, self_hash) of the last line of the first `size` bytes (which end with a newline), read backwards."""
    if size < 2:
        return None
    pos, end = size - 1, size - 1                         # end: the terminator of the last line
    while pos > 0 and end - pos <= MAX_LINE_BYTES + 2:
        step = min(1 << 16, pos)
        f.seek(pos - step)
        chunk = f.read(step)
        k = chunk.rfind(b"\n")
        if k != -1:
            return _entry_at(f, pos - step + k + 1, size)
        pos -= step
    return _entry_at(f, 0, size) if pos == 0 else None


def _write_state(path: str, f: BinaryIO, n: int, lines: int, last: str, first: str) -> None:
    """Best effort: the append is already durable; a state that cannot be written only means a full read next time."""
    try:
        size = os.fstat(f.fileno()).st_size
        digest = _prefix_sha256(f, size)
        if digest is None:
            return
        body = json.dumps({"version": STATE_VERSION, "size": size, "sha256": digest, "n": n, "lines": lines,
                           "last": last, "first": first}, sort_keys=True).encode()
        tmp = path + STATE_SUFFIX + ".tmp"
        with open(tmp, "wb") as g:
            g.write(body)
            g.flush(); os.fsync(g.fileno())
        os.replace(tmp, path + STATE_SUFFIX)
    except OSError as e:
        _log.warning("ledger %s: append state not written (%s): the next append reads the whole ledger", path, e)


class Ledger:
    """A single JSONL file. `append(data)` parses only the lines added since this writer's last append, after checking
    by SHA-256 that the bytes before them are unchanged (otherwise it reads the whole file, as before 15/11/2026);
    the check itself reads the file once, at hashing speed."""

    def __init__(self, path: str, tip_key: Optional[object] = None, allow_unlocked: bool = False):
        # allow_unlocked=True is the ONLY way to append on a filesystem without flock, and it is the caller's
        # declared acceptance that concurrent appends may fork the chain (fail-closed by default)
        self.allow_unlocked = allow_unlocked
        self.path = path
        self._tip_key = tip_key   # (sk, pk_hex) from omega_cra_evol.signing.load_key(): signed chain tip after each append
        d = os.path.dirname(os.path.abspath(path))
        os.makedirs(d, exist_ok=True)

    # ── write ──────────────────────────────────────────────────────────────
    def append(self, data: Dict[str, Any], ts: Optional[str] = None) -> Dict[str, Any]:
        canonical_bytes(data)   # refuse floats / NaN EARLY (never store what the verifiers reject)
        with open(self.path, "ab+") as f:
            if not _lock(f) and not self.allow_unlocked:
                raise RuntimeError("ledger: exclusive lock unavailable on this filesystem; refusing to append "
                                   "(pass allow_unlocked=True to accept unserialised appends explicitly)")
            start = _cached_start(self.path, f)
            idx, prev, first, unterminated, lines_before = _tail_state(f, start)
            entry = {"idx": idx, "ts": ts or _now_ts(), "prev_hash": prev, "data": data}
            self_hash = entry_hash(entry)
            entry["self_hash"] = self_hash
            line = canonical_bytes(entry) + b"\n"
            if len(line) - 1 > MAX_LINE_BYTES:   # content without the terminator
                raise ValueError(f"record would exceed {MAX_LINE_BYTES} bytes on one line: the verifiers refuse it, so it is not written")
            if nesting_depth(line.decode("utf-8")) > MAX_DEPTH:   # the LINE's depth (entry adds a level over data): what every reader bounds
                raise ValueError(f"record would nest deeper than {MAX_DEPTH} on its ledger line: the verifiers refuse it, so it is not written")
            f.seek(0, os.SEEK_END)
            end = f.tell()
            if unterminated:
                _log.warning("ledger %s ended without newline (crash or truncation): line closed before the new record", self.path)
            data = memoryview((b"\n" if unterminated else b"") + line)
            fd = f.fileno()
            try:   # unbuffered and whole, or not at all: a short write (full disk, file size limit) never leaves half a line
                while data:
                    data = data[os.write(fd, data):]
                os.fsync(fd)
            except BaseException as e:
                try:
                    os.ftruncate(fd, end)   # back to the bytes this call found (it holds the exclusive lock)
                    os.fsync(fd)
                    left = "the ledger is left as it was"
                except OSError:
                    left = "the ledger could not be truncated back and may end in part of the line"
                if isinstance(e, OSError):   # the record could not be delivered to the ledger: exit 74, as a promised file
                    from .outputs import OutputNotWritten
                    raise OutputNotWritten(f"ledger {self.path}: {e.strerror or e}; nothing was recorded, {left}") from None
                raise
            _write_state(self.path, f, idx + 1, lines_before + 1,   # an unterminated last line was already counted
                         self_hash, first if idx > 0 else self_hash)
            if self._tip_key is not None:
                from .signing import write_tip
                from .outputs import TipNotWritten
                try:
                    write_tip(self.path + ".tip.json", self._tip_key, idx + 1, first if idx > 0 else entry["self_hash"], entry["self_hash"])
                except OSError as e:   # write_tip raises OutputNotWritten, whose text already names the tip's path
                    raise TipNotWritten(f"{e}; record {idx} is in the ledger, the tip still names "
                                        f"the previous entry") from None
        return entry

    # ── read / verify ──────────────────────────────────────────────────────
    def entries(self, f: Optional[BinaryIO] = None) -> Iterator[Dict[str, Any]]:
        """The parsed entries of the ledger file, or of `f` (an already-open binary file, e.g. from open_regular())."""
        if f is None:
            if not os.path.exists(self.path):
                return
            with open_regular(self.path) as g:
                yield from self.entries(g)
            return
        while True:
            raw = f.readline(MAX_LINE_BYTES + 2)          # bounded read: a hostile line is never buffered whole
            if not raw:
                break
            if not raw.endswith(b"\n") and len(raw) == MAX_LINE_BYTES + 2:
                raise ValueError(f"ledger line exceeds {MAX_LINE_BYTES} bytes (cryptovalid profile: refused, never truncated)")
            content = line_content(raw)
            if len(content) > MAX_LINE_BYTES:             # the bound is on the content, terminator excluded, BEFORE the blank test, in all four
                raise ValueError(f"ledger line exceeds {MAX_LINE_BYTES} bytes (cryptovalid profile: refused, never truncated)")
            if is_blank_line(content):
                continue
            yield parse_line(content.decode("utf-8"))   # NaN/Infinity are not JSON: fail; invalid UTF-8: fail

    def verify(self, entries: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """Snapshot verification: every self_hash recomputes, every prev_hash links, idx contiguous, non-empty.
        Does NOT see a truncated tail (a shorter prefix is a valid chain): use the signed tip / cryptovalid.
        `entries`: an already-read list (the verifier reads the file ONCE and verifies that snapshot); a list is
        appended to only while the file is being read here, so a caller can pass `[]` to collect what was parsed."""
        failures: List[str] = []
        prev, n = GENESIS, 0
        try:
            for e in (self.entries() if entries is None else entries):
                if not isinstance(e, dict):
                    failures.append(f"entry {n}: not an object (JSON {type(e).__name__})")
                    break
                if type(e.get("idx")) is not int or e.get("idx") != n:   # `true` == 1 in Python: refuse the type, not just the value
                    failures.append(f"entry {n}: idx {e.get('idx')!r} not sequential")
                if e.get("prev_hash") != prev:
                    failures.append(f"entry {n}: prev_hash does not link")
                if entry_hash(e) != e.get("self_hash"):
                    failures.append(f"entry {n}: self_hash mismatch")
                prev = e.get("self_hash", prev) if isinstance(e.get("self_hash"), str) else prev
                n += 1
        except (ValueError, TypeError, RecursionError, OSError) as ex:
            failures.append(f"unparsable line: {type(ex).__name__}: {str(ex)[:120]}")
        if n == 0:
            failures.append("empty_ledger: zero entries, nothing to verify")
        return {"chain_ok": not failures, "entries": n, "failures": failures[:10], "last_self_hash": prev}
