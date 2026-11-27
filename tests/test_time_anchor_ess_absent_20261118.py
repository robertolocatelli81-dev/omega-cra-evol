# SPDX-License-Identifier: AGPL-3.0-or-later
"""18/11/2026 — spec/TIME_ANCHOR.md §9 (amendment written before the code): §5 step 8 with more than one ESSCertID,
§5 step 7 `signer_certificate_absent`, §3 genTime as the authority.

1. More than one ESSCertID. RFC 2634 §5.4 / RFC 5035: the first ESSCertID is the signer certificate; the ones after it
   limit the certificates of the path. OpenSSL's `ts -verify` asks every ESSCertID to be in the chain it built, so with
   a pinned CA below the last listed certificate a valid token was refused ("ess cert id not found": the Sectigo case
   measured by cryptovalid-opencore on 18/11/2026, the same command as 0.12.0's). Generative, as cryptovalid-opencore's
   test_tsa_ess_cert_ids_20261118.py (same author), on tokens over this package's §2 imprint: a root R, an intermediate
   I, the TSA certificate S, an unrelated CA X; sid issuerAndSerialNumber / subjectKeyIdentifier x signingCertificate
   (SHA-1) / signingCertificateV2 (SHA-256, SHA-384 explicit) x ESSCertID lists x issuerSerial absent / right / wrong on
   the first / wrong on a later one x pin S, I, R, X. The expected answer is computed by `expected`, from the rule as
   the spec writes it, not from the code.
2. Signer certificate absent. A token without its signer's certificate (certReq FALSE, RFC 3161 §2.4.1) and the
   certificate not pinned: `signer_certificate_absent`, `"ok": None` (ETSI EN 319 102-1 V1.4.1 §5.2.3.3), the function
   still False; never presumed (a certificates field openssl cannot read stays `signature_invalid`, §5.3.4).
3. genTime is the authority: a renewal earlier than the record before it by less than 2^-22 s has the same `t`;
   `verify` refuses it ("timestamp not monotonic").
Positive control: run on 4557a1f (0.12.0 + SBOM work), this file fails (measured, CHANGELOG 0.13.0)."""
import base64
import copy
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from omega_cra_evol import time_anchor as TA  # noqa: E402
from omega_cra_evol.longterm import LongTermEvidence, Signer, register_algorithm  # noqa: E402

NEEDS = unittest.skipUnless(shutil.which("openssl"), "needs openssl")
register_algorithm("test-ess", gen=lambda: ("sk", "pk-ess-fixed"), sign=lambda sk, m: m.hex(),
                   verify=lambda pub, sig, m: sig == m.hex())
D = hashlib.sha3_256(b"ESSCertID lists, signer absent, genTime").hexdigest()
OID_SC, OID_SC2 = "1.2.840.113549.1.9.16.2.12", "1.2.840.113549.1.9.16.2.47"
EXT = ("[ req ]\ndistinguished_name = dn\n[ dn ]\n"
       "[ ca ]\nbasicConstraints = critical,CA:TRUE\nkeyUsage = critical,keyCertSign,cRLSign\nsubjectKeyIdentifier = hash\n"
       "[ tsa ]\nextendedKeyUsage = critical,timeStamping\nbasicConstraints = CA:FALSE\nsubjectKeyIdentifier = hash\n"
       "authorityKeyIdentifier = keyid\n")


def der(tag, v):
    return TA._tlv(tag, v)


def oid(dotted):
    a = [int(x) for x in dotted.split(".")]
    body = bytes([40 * a[0] + a[1]])
    for n in a[2:]:
        enc = [n & 0x7F]
        n >>= 7
        while n:
            enc.append(0x80 | (n & 0x7F))
            n >>= 7
        body += bytes(reversed(enc))
    return der(0x06, body)


def integer(n):
    return der(0x02, n.to_bytes(n.bit_length() // 8 + 1, "big", signed=True))


def pem(d):
    return b"-----BEGIN CERTIFICATE-----\n" + base64.encodebytes(d) + b"-----END CERTIFICATE-----\n"


def first_der(pem_bytes):
    """the DER of the first PEM certificate (the bench does not use the code under test for it)"""
    b = pem_bytes.split(b"-----BEGIN CERTIFICATE-----")[1].split(b"-----END CERTIFICATE-----")[0]
    return base64.b64decode(b"".join(b.split()))


def issuer_serial(cert):
    """(issuer Name TLV, serial int) of a DER certificate"""
    tbs = TA._items(TA._items(TA._one(cert, 0x30))[0][1])
    k = 1 if tbs[0][0] == 0xA0 else 0
    return der(0x30, tbs[k + 2][1]), int.from_bytes(tbs[k][1], "big", signed=True)


def run(*c):
    return subprocess.run(c, check=True, capture_output=True, timeout=60)


class Pki:
    """root R -> intermediate I -> TSA certificate S (timeStamping, subjectKeyIdentifier); X an unrelated CA"""

    def __init__(self, d):
        self.d = d
        j = self.j
        with open(j("ext.cnf"), "w") as f:
            f.write(EXT)
        ec = ("-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes")
        for n in ("R", "X"):
            run("openssl", "req", "-x509", *ec, "-keyout", j(n + ".key"), "-out", j(n + ".crt"), "-subj", f"/CN=ess-{n}",
                "-days", "2", "-config", j("ext.cnf"), "-extensions", "ca")
        for n, ca, ext in (("I", "R", "ca"), ("S", "I", "tsa")):
            run("openssl", "req", *ec, "-keyout", j(n + ".key"), "-out", j(n + ".csr"), "-subj", f"/CN=ess-{n}",
                "-config", j("ext.cnf"))
            run("openssl", "x509", "-req", "-in", j(n + ".csr"), "-CA", j(ca + ".crt"), "-CAkey", j(ca + ".key"),
                "-CAcreateserial", "-out", j(n + ".crt"), "-days", "2", "-extfile", j("ext.cnf"), "-extensions", ext)
        self.cert = {}
        for n in ("R", "X", "I", "S"):
            with open(j(n + ".crt"), "rb") as f:
                self.cert[n] = first_der(f.read())
        with open(j("serial"), "w") as f:
            f.write("01\n")
        with open(j("tsa.cnf"), "w") as f:
            f.write(f"[ tsa ]\ndefault_tsa = t1\n[ t1 ]\nserial = {j('serial').replace(os.sep, '/')}\ncrypto_device = builtin\n"
                    f"signer_cert = {j('S.crt').replace(os.sep, '/')}\nsigner_key = {j('S.key').replace(os.sep, '/')}\nsigner_digest = sha256\n"
                    "default_policy = 1.2.3.4.1\ndigests = sha256\ness_cert_id_alg = sha256\ness_cert_id_chain = no\n")
        out = run("openssl", "x509", "-in", j("S.crt"), "-noout", "-ext", "subjectKeyIdentifier").stdout.decode()
        self.ski = bytes.fromhex(out.strip().splitlines()[-1].strip().replace(":", ""))

    def j(self, n):
        return os.path.join(self.d, n)

    def tstinfo(self, imprint_hex, gen_time=None):
        """the TSTInfo of `openssl ts -reply` over the imprint; its genTime replaced by `gen_time` when given"""
        j = self.j
        run("openssl", "ts", "-query", "-digest", imprint_hex, "-sha256", "-cert", "-out", j("q.tsq"))
        run("openssl", "ts", "-reply", "-queryfile", j("q.tsq"), "-config", j("tsa.cnf"), "-section", "t1",
            "-token_out", "-out", j("tok.der"))
        with open(j("tok.der"), "rb") as f:
            tok = f.read()
        sd = TA._signed_data(tok)
        tst = TA._one(TA._items(sd[2][1])[1][1], 0x04)
        if gen_time is None:
            return tst
        els = TA._items(TA._one(tst, 0x30))
        return der(0x30, b"".join(der(t, gen_time.encode() if t == 0x18 else v) for t, v in els))

    def ess_id(self, name, alg, is_mode, wrong_hash=False):
        """one ESSCertID(v2) for certificate `name`; is_mode: None (absent), "ok", "bad" (serial + 1)"""
        c = self.cert[name]
        h = hashlib.new(alg, c).digest()
        if wrong_hash:
            h = bytes([h[0] ^ 1]) + h[1:]
        body = b""
        if alg == "sha384":
            body += der(0x30, oid("2.16.840.1.101.3.4.2.2"))
        body += der(0x04, h)
        if is_mode is not None:
            iss, serial = issuer_serial(c)
            body += der(0x30, der(0x30, der(0xA4, iss)) + integer(serial + (1 if is_mode == "bad" else 0)))
        return der(0x30, body)

    def token(self, tst, sid, attrs, certs=("S", "I", "R"), certs_field=True, flip=False):
        """a TimeStampToken over `tst`, signed with S's key; attrs: [(version "v1"/"v2", [ESSCertID DER])]"""
        a = [der(0x30, oid("1.2.840.113549.1.9.3") + der(0x31, oid("1.2.840.113549.1.9.16.1.4"))),
             der(0x30, oid("1.2.840.113549.1.9.4") + der(0x31, der(0x04, hashlib.sha256(tst).digest())))]
        for ver, ids in attrs:
            a.append(der(0x30, oid(OID_SC if ver == "v1" else OID_SC2) + der(0x31, der(0x30, der(0x30, b"".join(ids))))))
        signed = b"".join(sorted(a))
        with open(self.j("attrs.der"), "wb") as f:
            f.write(der(0x31, signed))
        sig = run("openssl", "dgst", "-sha256", "-sign", self.j("S.key"), self.j("attrs.der")).stdout
        if flip:
            sig = sig[:-1] + bytes([sig[-1] ^ 1])
        if sid == "ias":
            iss, serial = issuer_serial(self.cert["S"])
            version, sid_der = 1, der(0x30, iss + integer(serial))
        else:
            version, sid_der = 3, der(0x80, self.ski)
        si = der(0x30, integer(version) + sid_der + der(0x30, oid("2.16.840.1.101.3.4.2.1")) + der(0xA0, signed)
                 + der(0x30, oid("1.2.840.10045.4.3.2")) + der(0x04, sig))
        cf = b""
        if certs_field:
            cf = der(0xA0, b"".join(self.cert[c] if isinstance(c, str) else c for c in certs))
        sd = der(0x30, integer(3) + der(0x31, der(0x30, oid("2.16.840.1.101.3.4.2.1")))
                 + der(0x30, oid("1.2.840.113549.1.9.16.1.4") + der(0xA0, der(0x04, tst))) + cf + der(0x31, si))
        return der(0x30, oid("1.2.840.113549.1.7.2") + der(0xA0, sd))


SIGNER = Signer("test-ess")
IMPRINT = LongTermEvidence(D).anchor_imprint(SIGNER)


def sealed(tok, lte=None):
    lte = lte or LongTermEvidence(D)
    lte.seal(SIGNER, None, ts_source="rfc3161", token_b64=base64.b64encode(tok).decode())
    return lte


def answer(lte, pins):
    fn = TA.make_timestamp_trust_fn(lte, pins)
    ok = fn(lte.records[-1])
    return ok, fn.log[-1]


LISTS = {
    "S": [("S", False)], "S,I": [("S", False), ("I", False)], "S,I,R": [("S", False), ("I", False), ("R", False)],
    "S,R": [("S", False), ("R", False)], "S,X": [("S", False), ("X", False)], "S,S": [("S", False), ("S", False)],
    "I,S": [("I", False), ("S", False)], "X,S": [("X", False), ("S", False)], "S~": [("S", True)],
    "S~,I,R": [("S", True), ("I", False), ("R", False)],
}


def expected(ids, is_mode, pin):
    """spec §5 step 8 (0.13.0) for one attribute: True (verified) or False (not_issued_by_pinned_tsa)"""
    if len(set(ids)) != len(ids):
        return False                                       # the same certificate listed twice (closed)
    if ids[0] != ("S", False) or is_mode == "first_bad":
        return False                                       # the first ESSCertID is the signer's, or the token is refused
    if is_mode == "later_bad" and ids[1][0] in {"S", "I", "R", pin}:
        return False                                       # an issuerSerial that does not name the certificate it hashes
    if pin == "X":
        return False
    allowed = None if len(ids) == 1 else {c for c, _ in ids}
    if pin == "R" and allowed is not None and "I" not in allowed:
        return False                                       # the path needs I, which the list leaves out
    return True


@NEEDS
class EssCertIdLists(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.td = tempfile.mkdtemp()
        cls.pki = Pki(cls.td)
        cls.tst = cls.pki.tstinfo(IMPRINT)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.td, ignore_errors=True)

    def ids(self, spec, alg, is_mode):
        out = []
        for n, (c, wrong) in enumerate(spec):
            m = None if is_mode is None else "ok"
            if (is_mode == "first_bad" and n == 0) or (is_mode == "later_bad" and n == 1):
                m = "bad"
            out.append(self.pki.ess_id(c, alg, m, wrong))
        return out

    def pinned(self, name):
        return [pem(self.pki.cert[name])]

    def test_generative(self):
        n, bad = 0, []
        for sid in ("ias", "ski"):
            for ver, alg in (("v1", "sha1"), ("v2", "sha256"), ("v2", "sha384")):
                for name, spec in LISTS.items():
                    if alg == "sha384" and len(spec) > 2:
                        continue
                    for is_mode in (None, "ok", "first_bad", "later_bad"):
                        if is_mode == "later_bad" and len(spec) < 2:
                            continue
                        tok = self.pki.token(self.tst, sid, [(ver, self.ids(spec, alg, is_mode))])
                        lte = sealed(tok)
                        for pin in ("S", "I", "R", "X"):
                            want = expected(spec, is_mode, pin)
                            ok, log = answer(lte, self.pinned(pin))
                            n += 1
                            if ok != want or (not ok and log["reason"] != "not_issued_by_pinned_tsa"):
                                bad.append((sid, ver, name, is_mode, pin, want, ok, log["reason"],
                                            (log["detail"] or "")[:70]))
        self.assertGreater(n, 600)
        self.assertEqual(bad, [], f"{len(bad)} of {n} cases differ")

    def test_the_measured_shape_pin_below_the_last_listed(self):
        """the Sectigo shape: signer, CA and root listed, the CA pinned (refused by `ts -verify`, 0.12.0)"""
        tok = self.pki.token(self.tst, "ias", [("v2", self.ids(LISTS["S,I,R"], "sha256", "ok"))])
        ok, log = answer(sealed(tok), self.pinned("I"))
        self.assertTrue(ok, log)
        ok, log = answer(sealed(tok), self.pinned("X"))                    # control: another CA
        self.assertEqual((ok, log["reason"]), (False, "not_issued_by_pinned_tsa"))

    def test_two_attributes_limit_together(self):
        def i(c, a):
            return self.pki.ess_id(c, a, "ok")
        for sid in ("ias", "ski"):
            for v1, v2, want in ((["S"], ["S", "I"], True), (["S", "R"], ["S", "I"], False),
                                 (["S", "I", "R"], ["S", "I"], True), (["S", "I"], ["I", "S"], False)):
                tok = self.pki.token(self.tst, sid, [("v1", [i(c, "sha1") for c in v1]), ("v2", [i(c, "sha256") for c in v2])])
                ok, log = answer(sealed(tok), self.pinned("R"))
                self.assertEqual(ok, want, (sid, v1, v2, log))

    def test_malformed_later_id_is_refused(self):
        p = self.pki
        good = p.ess_id("S", "sha256", "ok")
        short = der(0x30, der(0x04, hashlib.sha256(p.cert["I"]).digest()[:20]))
        unknown_alg = der(0x30, der(0x30, oid("1.2.3.4")) + der(0x04, b"\0" * 32))
        iss, serial = issuer_serial(p.cert["I"])
        two_names = der(0x30, der(0x04, hashlib.sha256(p.cert["I"]).digest())
                        + der(0x30, der(0x30, der(0xA4, iss) * 2) + integer(serial)))
        not_seq = der(0x04, hashlib.sha256(p.cert["I"]).digest())
        for sid in ("ias", "ski"):
            ok, log = answer(sealed(p.token(self.tst, sid, [("v2", [good, p.ess_id("X", "sha256", "ok")])])),
                             self.pinned("I"))
            self.assertTrue(ok, log)                                         # control
            for later in (short, unknown_alg, two_names, not_seq):
                ok, log = answer(sealed(p.token(self.tst, sid, [("v2", [good, later])])), self.pinned("I"))
                self.assertEqual((ok, log["reason"]), (False, "not_issued_by_pinned_tsa"), (sid, log))

    def test_route(self):
        p = self.pki
        one = p.token(self.tst, "ias", [("v2", [p.ess_id("S", "sha256", "ok")])])
        two = p.token(self.tst, "ias", [("v2", [p.ess_id("S", "sha256", "ok"), p.ess_id("I", "sha256", None)])])
        self.assertFalse(TA._ess_lists_more_than_one(one))
        self.assertTrue(TA._ess_lists_more_than_one(two))
        self.assertFalse(TA._ess_lists_more_than_one(b"\x30\x00"))


@NEEDS
class SignerAbsent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.td = tempfile.mkdtemp()
        cls.pki = Pki(cls.td)
        os.makedirs(os.path.join(cls.td, "o"))
        cls.other = Pki(os.path.join(cls.td, "o"))
        cls.tst = cls.pki.tstinfo(IMPRINT)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.td, ignore_errors=True)

    def tok(self, sid, certs, field=True, flip=False):
        return self.pki.token(self.tst, sid, [("v2", [self.pki.ess_id("S", "sha256", "ok")])], certs=certs,
                              certs_field=field, flip=flip)

    def test_generative(self):
        p, o = self.pki, self.other
        root_only = [pem(p.cert["R"])]
        with_leaf = [pem(p.cert["R"]), pem(p.cert["S"])]
        with_chain = [pem(p.cert["R"]), pem(p.cert["I"]), pem(p.cert["S"])]
        n, bad = 0, []
        for sid in ("ias", "ski"):
            for certs, field in (((), True), ((), False), (("I", "R"), True), (("R",), True),
                                 (("S", "I", "R"), True), (("I", "S"), True)):
                has_signer = "S" in certs
                for pins, name in ((root_only, "root"), (with_leaf, "leaf"), (with_chain, "chain"),
                                   ([pem(o.cert["R"])], "other")):
                    for flip in (False, True):
                        ok, log = answer(sealed(self.tok(sid, certs, field, flip)), pins)
                        signer_found = has_signer or name in ("leaf", "chain")
                        if not signer_found:
                            want = (False, None, "signer_certificate_absent")
                        elif flip:
                            want = (False, False, "signature_invalid")
                        elif name == "other":
                            want = (False, False, "not_issued_by_pinned_tsa")
                        elif "I" not in certs and name == "root":
                            want = (False, False, "not_issued_by_pinned_tsa")     # no path from S to R without I
                        # pinned leaf: -partial_chain ends the chain at the pin (spec §5 step 8 (c)), I is not needed
                        else:
                            want = (True, True, None)
                        got = (ok, log["ok"], log["reason"])
                        n += 1
                        if got != want:
                            bad.append((sid, certs, field, name, flip, want, got, (log["detail"] or "")[:60]))
        self.assertEqual(n, 96)
        self.assertEqual(bad, [], f"{len(bad)} of {n}" + "\n".join(map(str, bad)))

    def test_absence_is_never_presumed(self):
        """a certificates field with an element openssl cannot read, another CertificateChoices, a sid openssl cannot
        match and this reader cannot read: signature_invalid, as before"""
        for extra in (der(0x30, integer(1)), der(0xA1, b"\x05\x00")):
            ok, log = answer(sealed(self.tok("ias", ("I", "R", extra))), [pem(self.pki.cert["R"])])
            self.assertEqual((ok, log["ok"], log["reason"]), (False, False, "signature_invalid"), (extra, log))

    def test_reason_is_in_the_closed_list(self):
        self.assertIn("signer_certificate_absent", TA.REASONS)


@NEEDS
class GenTimeIsTheAuthority(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.td = tempfile.mkdtemp()
        cls.pki = Pki(cls.td)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.td, ignore_errors=True)

    def chain(self, g0, g1):
        p = self.pki
        lte = LongTermEvidence(D)
        for g in (g0, g1):
            tst = p.tstinfo(lte.anchor_imprint(SIGNER), gen_time=g)
            sealed(p.token(tst, "ias", [("v2", [p.ess_id("S", "sha256", "ok")])]), lte)
        return lte

    def verdict(self, lte):
        fn = TA.make_timestamp_trust_fn(lte, [pem(self.pki.cert["R"])])
        v = lte.verify(now=1.9e9, timestamp_trust_fn=fn)
        return v, fn.log

    def test_collapsed_genTimes(self):
        day = TA_day()
        a, b = day + ".1234568Z", day + ".1234567Z"
        lte = self.chain(a, b)
        self.assertEqual(lte.records[0]["t"], lte.records[1]["t"])         # the same t: the double cannot tell them
        v, log = self.verdict(lte)
        self.assertIn("record 1: timestamp not monotonic", v["reasons"])
        self.assertEqual([e["detail"] for e in log], [a, b])                # the genTime strings are what is reported
        v, _ = self.verdict(self.chain(b, a))                               # control: the right order passes
        self.assertNotIn("record 1: timestamp not monotonic", v["reasons"])
        self.assertEqual(v["temporal_trust"], "verified", v)
        v, _ = self.verdict(self.chain(a, a))                               # equal genTime: not earlier
        self.assertNotIn("record 1: timestamp not monotonic", v["reasons"])
        v, _ = self.verdict(self.chain(day + ".123457Z", day + ".123456Z"))   # control: apart in t, refused before too
        self.assertIn("record 1: timestamp not monotonic", v["reasons"])
        v = lte.verify(now=1.9e9)                                           # no trust function: the same order check
        self.assertIn("record 1: timestamp not monotonic", v["reasons"])

    def test_exact_value(self):
        from fractions import Fraction
        from omega_cra_evol.longterm import _exact_gen_time
        lte = self.chain(TA_day() + ".5Z", TA_day() + "Z")
        e0, e1 = (_exact_gen_time(r) for r in lte.records)
        self.assertEqual(e0 - e1, Fraction(1, 2))
        r = copy.deepcopy(lte.records[0])
        r["t"] = repr(float(r["t"]) + 1)                                    # t not the rendering: float(t) decides
        self.assertIsNone(_exact_gen_time(r))
        self.assertIsNone(_exact_gen_time({"ts_source": "asserted", "t": "1.0"}))


def TA_day():
    import time
    return time.strftime("%Y%m%d%H%M%S", time.gmtime(time.time() + 120))   # after the certificates' notBefore


if __name__ == "__main__":
    unittest.main()
