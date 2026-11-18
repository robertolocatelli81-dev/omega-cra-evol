# SPDX-License-Identifier: AGPL-3.0-or-later
"""spec/TIME_ANCHOR.md §5 step 8 as amended on 17/11/2026 (0.13.0): a token whose SignerInfo names its signer by
subjectKeyIdentifier.

RFC 5652 §5.3 allows `sid` to be issuerAndSerialNumber or subjectKeyIdentifier. openssl `ts -verify` reads the token as
PKCS #7 and refuses the second form with an ASN.1 error, so 0.12.0 refused a valid token of that kind as
`not_issued_by_pinned_tsa` (the defect cryptovalid-opencore measured on 16/11/2026 in the same call; ported from its
SPEC §11 step 7 and test_tsa_signer_key_id_20261116.py, same author).

Everything is made with openssl on this machine: a CA and TSA certificates carrying a subjectKeyIdentifier, a token from
`openssl ts -reply` over the record's §2 imprint, and the same TSTInfo re-signed by `openssl cms -sign -keyid -cades`
(sid = subjectKeyIdentifier, an ESS signingCertificateV2 attribute). Positive control: `SealedKeyId` run on the tree of
v0.12.0 fails 4 of its 7 tests, each a valid key-identified record refused as `not_issued_by_pinned_tsa` with the ASN.1
error of `ts -verify` (`Type=PKCS7`) (measured 17/11/2026, OpenSSL 3.0.22, Python 3.13); the issuerAndSerialNumber
record passes there and here. Negatives: the key identifier of another certificate, another TSA's
key, no ESS attribute, a certificate without timeStamping, a `tsa` field naming another TSA, a system certificate
directory that trusts another CA, two SignerInfos, an openssl without `-no-CAstore`; then each check of the step on the
helper with one field changed, and generative mutations of every DER element the step reads."""
import base64
import copy
import hashlib
import os
import random
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
from omega_cra_evol.longterm import LongTermEvidence, Signer, register_algorithm  # noqa: E402
from omega_cra_evol import time_anchor as TA  # noqa: E402

NEEDS = unittest.skipUnless(shutil.which("openssl"), "needs openssl")
try:
    import cryptography  # noqa: F401
    HAVE_CRYPTOGRAPHY = True
except ImportError:
    HAVE_CRYPTOGRAPHY = False
register_algorithm("test-keyid", gen=lambda: ("sk", "pk-" + os.urandom(4).hex()), sign=lambda sk, m: m.hex(),
                   verify=lambda pub, sig, m: sig == m.hex())
D = hashlib.sha3_256(b"key-identified signer").hexdigest()
OID_TSTINFO = "1.2.840.113549.1.9.16.1.4"
EXT = ("[ v3_ca ]\nbasicConstraints = critical,CA:TRUE\nkeyUsage = critical,keyCertSign,cRLSign\n"
       "subjectKeyIdentifier = hash\n"
       "[ v3_tsa ]\nextendedKeyUsage = critical,timeStamping\nbasicConstraints = CA:FALSE\n"
       "subjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid\n"
       "[ v3_plain ]\nbasicConstraints = CA:FALSE\nkeyUsage = critical,digitalSignature\nsubjectKeyIdentifier = hash\n"
       "[ v3_tsa_san ]\nextendedKeyUsage = critical,timeStamping\nbasicConstraints = CA:FALSE\n"
       "subjectKeyIdentifier = hash\nsubjectAltName = DNS:tsa.example\n"
       "[ v3_badca ]\nbasicConstraints = critical,CA:TRUE\nkeyUsage = critical,digitalSignature\n"
       "subjectKeyIdentifier = hash\n")


def _run(*cmd):
    return subprocess.run(cmd, check=True, capture_output=True, timeout=60)


class Lab:
    """a CA with a subjectKeyIdentifier and certificates it issued; tokens by openssl ts, re-signed by openssl cms"""
    ess_alg = "sha256"

    def __init__(self, td, name, ca_ext="v3_ca", tsa_ext="v3_tsa"):
        self.d = os.path.join(td, name)
        os.makedirs(self.d)
        j = self.j
        with open(j("ext.cnf"), "w") as f:
            f.write(EXT)
        with open(j("req.cnf"), "w") as f:
            f.write("[ req ]\ndistinguished_name = dn\n[ dn ]\n" + EXT)
        _run("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
             "-keyout", j("ca.key"), "-out", j("ca.crt"), "-subj", f"/CN={name}-ca", "-days", "2",
             "-config", j("req.cnf"), "-extensions", ca_ext)
        for cert, ext in (("tsa", tsa_ext), ("plain", "v3_plain")):
            _run("openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                 "-keyout", j(f"{cert}.key"), "-out", j(f"{cert}.csr"), "-subj", f"/CN={name}-{cert}",
                 "-config", j("req.cnf"))
            _run("openssl", "x509", "-req", "-in", j(f"{cert}.csr"), "-CA", j("ca.crt"), "-CAkey", j("ca.key"),
                 "-CAcreateserial", "-out", j(f"{cert}.crt"), "-days", "2", "-extfile", j("ext.cnf"), "-extensions", ext)
        with open(j("serial"), "w") as f:
            f.write("01\n")

    def j(self, n):
        return os.path.join(self.d, n)

    @property
    def ca(self):
        return self.j("ca.crt")

    def token(self, imprint_hex, tsa_name=False, chain=False):
        """the DER of a TimeStampToken of `openssl ts -reply` (sid = issuerAndSerialNumber) over a SHA-256 imprint"""
        j = self.j
        with open(j("tsa.cnf"), "w") as f:
            f.write(f"[ tsa ]\ndefault_tsa = t1\n[ t1 ]\nserial = {j('serial')}\ncrypto_device = builtin\n"
                    f"signer_cert = {j('tsa.crt')}\ncerts = {j('ca.crt')}\nsigner_key = {j('tsa.key')}\n"
                    "signer_digest = sha256\ndefault_policy = 1.2.3.4.1\ndigests = sha256\naccuracy = secs:1\n"
                    f"ordering = yes\ntsa_name = {'yes' if tsa_name else 'no'}\ness_cert_id_chain = {'yes' if chain else 'no'}\n"
                    f"ess_cert_id_alg = {self.ess_alg}\n")
        _run("openssl", "ts", "-query", "-digest", imprint_hex, "-sha256", "-cert", "-out", j("q.tsq"))
        _run("openssl", "ts", "-reply", "-queryfile", j("q.tsq"), "-config", j("tsa.cnf"), "-section", "t1",
             "-token_out", "-out", j("tok.der"))
        with open(j("tok.der"), "rb") as f:
            return f.read()

    def resign(self, token, signer="tsa", ess=True, extra_signer=None):
        """the TSTInfo of `token` signed again by openssl cms with `signer`'s key, the signer named by its key identifier"""
        j = self.j
        with open(j("in.der"), "wb") as f:
            f.write(token)
        _run("openssl", "cms", "-verify", "-noverify", "-inform", "DER", "-in", j("in.der"), "-out", j("tst.der"))
        more = []
        if extra_signer:
            more = ["-signer", extra_signer.j("tsa.crt"), "-inkey", extra_signer.j("tsa.key")]
        _run("openssl", "cms", "-sign", "-binary", "-nodetach", "-econtent_type", OID_TSTINFO, "-keyid",
             *(["-cades"] if ess else []), "-md", "sha256", "-nosmimecap", "-signer", j(f"{signer}.crt"),
             "-inkey", j(f"{signer}.key"), *more, "-certfile", j("ca.crt"), "-in", j("tst.der"), "-outform", "DER",
             "-out", j("ski.der"))
        with open(j("ski.der"), "rb") as f:
            return f.read()


def der(tag, v):
    n = len(v)
    ln = bytes([n]) if n < 0x80 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag]) + ln + v


def tree(b):
    """a DER element as [tag, children] when constructed, [tag, bytes] when primitive"""
    (t, v), = TA._items(b)
    return [t, [tree(der(ct, cv)) for ct, cv in TA._items(v)]] if t & 0x20 else [t, v]


def enc(n):
    return der(n[0], b"".join(enc(c) for c in n[1]) if isinstance(n[1], list) else n[1])


def signer_info(tok):
    """the SignerInfo node of a token's tree (ContentInfo / [0] / SignedData / signerInfos / SignerInfo)"""
    return tok[1][1][1][0][1][-1][1][0]


def ess_v2(si):
    """the ESSCertIDv2 list of the signingCertificateV2 attribute of a SignerInfo node"""
    for a in si[1][3][1]:
        if TA._oid_of(a[1][0][1]) == TA._OID_SIGNING_CERTIFICATE_V2:
            return a[1][1][1][0][1][0][1]
    raise AssertionError("no signingCertificateV2")


def ski_of(cert_path):
    out = _run("openssl", "x509", "-in", cert_path, "-noout", "-ext", "subjectKeyIdentifier").stdout.decode()
    return bytes.fromhex(out.strip().splitlines()[-1].strip().replace(":", ""))


def sealed(lab, make=None, signer_alg="test-keyid"):
    """a one-record chain whose token is `make(token over the record's imprint)` (default: re-signed by key id)"""
    s = Signer(signer_alg)
    lte = LongTermEvidence(D)
    tok = lab.token(lte.anchor_imprint(s))
    tok = (make or lab.resign)(tok)
    lte.seal(s, None, ts_source="rfc3161", token_b64=base64.b64encode(tok).decode())
    return lte


def answer(lte, pins):
    fn = TA.make_timestamp_trust_fn(lte, pins)
    return [fn(r) for r in lte.records], [(e["reason"], e["detail"]) for e in fn.log]


def first_der(pem_path):
    with open(pem_path, "rb") as f:
        return TA._pem_block_der(f.read().split(b"-----BEGIN CERTIFICATE-----")[1])


@NEEDS
class SealedKeyId(unittest.TestCase):
    """through the public function, on sealed records (the only class that also runs on v0.12.0: the positive control)"""

    @classmethod
    def setUpClass(cls):
        cls.td = tempfile.mkdtemp()
        cls.lab, cls.other = Lab(cls.td, "a"), Lab(cls.td, "b")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.td, ignore_errors=True)

    def test_issuer_and_serial_record_unchanged(self):
        ok, log = answer(sealed(self.lab, make=lambda t: t), [self.lab.ca])
        self.assertEqual((ok, log[0][0]), ([True], None), log)

    def test_valid_record_is_verified(self):
        lte = sealed(self.lab)
        raw = base64.b64decode(lte.records[0]["token_b64"])
        self.assertIn(b"\x80" + bytes([len(ski_of(self.lab.j("tsa.crt")))]) + ski_of(self.lab.j("tsa.crt")), raw)
        for pins in ([self.lab.ca], [self.lab.j("tsa.crt")]):
            ok, log = answer(lte, pins)
            self.assertEqual((ok, log[0][0]), ([True], None), (pins, log))

    def test_openssl_ts_refuses_it(self):
        """the defect's cause: openssl ts -verify cannot read the SignerInfo; the issuerAndSerialNumber token passes"""
        s = Signer("test-keyid")
        imp = LongTermEvidence(D).anchor_imprint(s)
        plain = self.lab.token(imp)
        for tok, ok in ((plain, True), (self.lab.resign(plain), False)):
            p = os.path.join(self.td, "t.der")
            with open(p, "wb") as f:
                f.write(tok)
            r = subprocess.run(["openssl", "ts", "-verify", "-token_in", "-in", p, "-digest", imp, "-CAfile",
                                self.lab.ca, "-untrusted", self.lab.ca, "-partial_chain"], capture_output=True)
            self.assertEqual(r.returncode == 0 and b"Verification: OK" in r.stdout, ok, r.stderr[-300:])

    def test_another_tsa_key(self):
        lte = sealed(self.lab, make=self.other.resign)        # signed by b's TSA, a's CA pinned
        ok, log = answer(lte, [self.lab.ca])
        self.assertEqual((ok, log[0][0]), ([False], "not_issued_by_pinned_tsa"), log)
        self.assertEqual(answer(lte, [self.other.ca])[0], [True])

    def test_no_ess_attribute(self):
        ok, log = answer(sealed(self.lab, make=lambda t: self.lab.resign(t, ess=False)), [self.lab.ca])
        self.assertEqual((ok, log[0][0]), ([False], "not_issued_by_pinned_tsa"), log)
        self.assertIn("ESS", log[0][1])

    def test_certificate_without_time_stamping(self):
        ok, log = answer(sealed(self.lab, make=lambda t: self.lab.resign(t, signer="plain")), [self.lab.ca])
        self.assertEqual((ok, log[0][0]), ([False], "not_issued_by_pinned_tsa"), log)

    def test_tsa_field(self):
        s = Signer("test-keyid")
        for lab, good in ((self.lab, True), (self.other, False)):
            lte = LongTermEvidence(D)
            tok = self.lab.resign(lab.token(lte.anchor_imprint(s), tsa_name=True)) if good else \
                self.lab.resign(self.other.token(lte.anchor_imprint(s), tsa_name=True))
            lte.seal(s, None, ts_source="rfc3161", token_b64=base64.b64encode(tok).decode())
            ok, log = answer(lte, [self.lab.ca])
            self.assertEqual(ok, [good], log)
            if not good:
                self.assertEqual(log[0][0], "not_issued_by_pinned_tsa")
                self.assertIn("tsa field", log[0][1])


@NEEDS
class KeyIdNegatives(unittest.TestCase):
    """the 0.13.0 cases a key-identified token must not pass, through the public function"""

    @classmethod
    def setUpClass(cls):
        cls.td = tempfile.mkdtemp()
        cls.lab, cls.other = Lab(cls.td, "a"), Lab(cls.td, "b")
        cls.lte = sealed(cls.lab)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.td, ignore_errors=True)

    def with_token(self, raw):
        lte = LongTermEvidence(D, records=copy.deepcopy(self.lte.records))
        r = lte.records[0]
        r["token_b64"] = base64.b64encode(raw).decode()
        r["token_sha3"] = hashlib.sha3_256(r["token_b64"].encode()).hexdigest()
        r["sig"] = lte._msg(0, r, r.get("hash", "sha3-256")).hex()
        return lte

    def test_control(self):
        raw = base64.b64decode(self.lte.records[0]["token_b64"])
        self.assertEqual(answer(self.with_token(raw), [self.lab.ca])[0], [True])

    def test_key_id_of_another_certificate(self):
        """the sid rewritten to the key identifier of another certificate (sid is not signed): never verified"""
        raw = base64.b64decode(self.lte.records[0]["token_b64"])
        mine, theirs = ski_of(self.lab.j("tsa.crt")), ski_of(self.other.j("tsa.crt"))
        sid = bytes([0x80, len(mine)]) + mine
        self.assertEqual(raw.count(sid), 1)
        forged = self.with_token(raw.replace(sid, bytes([0x80, len(theirs)]) + theirs))
        for pins in ([self.lab.ca], [self.lab.ca, self.other.j("tsa.crt")], [self.other.ca, self.other.j("tsa.crt")]):
            ok, log = answer(forged, pins)
            self.assertEqual(ok, [False], (pins, log))
            if self.other.j("tsa.crt") in pins:
                self.assertIn(log[0][0], ("signature_invalid", "not_issued_by_pinned_tsa"), log)
            else:   # 0.13.0, spec §5 step 7: the certificate the sid names is nowhere -> not evaluated, never verified
                self.assertEqual(log[0][0], "signer_certificate_absent", log)

    def test_the_system_store_is_not_a_pin(self):
        """only the pinned certificates anchor: SSL_CERT_DIR trusting b's CA does not make b's token pass under a's pin"""
        store = os.path.join(self.td, "store")
        os.makedirs(store, exist_ok=True)
        shutil.copy(self.other.ca, os.path.join(store, "b-ca.pem"))
        _run("openssl", "rehash", store)
        lte = sealed(self.lab, make=self.other.resign)
        old = os.environ.get("SSL_CERT_DIR")
        os.environ["SSL_CERT_DIR"] = store
        try:
            r = subprocess.run(["openssl", "verify", "-purpose", "timestampsign", self.other.j("tsa.crt")],
                               capture_output=True)
            self.assertEqual(r.returncode, 0, r.stderr)                  # control: openssl trusts the directory
            ok, log = answer(lte, [self.lab.ca])
        finally:
            if old is None:
                del os.environ["SSL_CERT_DIR"]
            else:
                os.environ["SSL_CERT_DIR"] = old
        self.assertEqual((ok, log[0][0]), ([False], "not_issued_by_pinned_tsa"), log)

    def test_two_signer_infos(self):
        """two signers (a's TSA and b's TSA, both by key id) over the same TSTInfo: openssl ts -verify refuses two signers
        in its form ("there must be one signer"); this form refuses them too"""
        lte = sealed(self.lab, make=lambda t: self.lab.resign(t, extra_signer=self.other))
        raw = base64.b64decode(lte.records[0]["token_b64"])
        self.assertEqual(len(TA._signer_infos(raw)), 2)
        for pins in ([self.lab.ca], [self.lab.ca, self.other.ca]):
            ok, log = answer(lte, pins)
            self.assertEqual((ok, log[0][0]), ([False], "not_issued_by_pinned_tsa"), (pins, log))
            self.assertIn("2 written by openssl", log[0][1])                  # two signer certificates: not read
        leaf = first_der(self.lab.j("tsa.crt"))
        self.assertIn("2 SignerInfos", TA._key_id_anchor(raw, leaf, TA._pins_pem([self.lab.ca]), int(time.time()), self.td))

    def test_openssl_without_no_castore_did_not_run(self):
        """an openssl whose `verify` does not know -no-CAstore (before 3.0): no verdict, TimeAnchorNotRun"""
        bindir = os.path.join(self.td, "bin")
        os.makedirs(bindir, exist_ok=True)
        fake = os.path.join(bindir, "openssl")
        with open(fake, "w") as f:
            f.write("#!/bin/sh\nif [ \"$1\" = verify ]; then echo 'verify: Unknown option: -no-CAstore' >&2; exit 1; fi\n"
                    f"exec {shutil.which('openssl')} \"$@\"\n")
        os.chmod(fake, os.stat(fake).st_mode | stat.S_IXUSR)
        old = os.environ["PATH"]
        os.environ["PATH"] = bindir + os.pathsep + old
        try:
            self.assertEqual(shutil.which("openssl"), fake)
            fn = TA.make_timestamp_trust_fn(self.lte, [self.lab.ca])
            with self.assertRaises(TA.TimeAnchorNotRun):
                fn(self.lte.records[0])
            plain = sealed(self.lab, make=lambda t: t)                  # the other form does not call verify
            self.assertEqual(answer(plain, [self.lab.ca])[0], [True])
        finally:
            os.environ["PATH"] = old


@NEEDS
class AnchorParts(unittest.TestCase):
    """each check of the step for a key-identified signer, called on the step's own function with one field changed (the
    signature is step 7's, checked apart): the ESS hash, issuerSerial, the number of values and ESSCertIDs, the ESS
    hash algorithm, the tsa field, the name comparison, genTime, and a pinned leaf whose CA in the token cannot sign"""

    @classmethod
    def setUpClass(cls):
        cls.td = tempfile.mkdtemp()
        cls.lab = Lab(cls.td, "a")
        cls.leaf = first_der(cls.lab.j("tsa.crt"))
        cls.pins = TA._pins_pem([cls.lab.ca])
        cls.imp = LongTermEvidence(D).anchor_imprint(Signer("test-keyid"))
        cls.ski = cls.lab.resign(cls.lab.token(cls.imp))
        cls.at = int(time.time())

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.td, ignore_errors=True)

    def anchor(self, tok, at=None, pins=None, leaf=None):
        return TA._key_id_anchor(tok, leaf or self.leaf, pins or self.pins, at or self.at, self.td)

    def test_control(self):
        self.assertIsNone(self.anchor(self.ski))
        self.assertEqual(enc(tree(self.ski)), self.ski)                 # the tree rebuilds the same bytes
        self.assertTrue(TA._signer_named_by_key_id(self.ski))
        self.assertFalse(TA._signer_named_by_key_id(self.lab.token(self.imp)))

    def test_ess_cert_hash(self):
        t = tree(self.ski)
        cid = ess_v2(signer_info(t))[0][1]
        h = [x for x in cid if x[0] == 0x04][0]
        h[1] = bytes([h[1][0] ^ 1]) + h[1][1:]
        self.assertIn("certHash", self.anchor(enc(t)))

    def test_ess_issuer_serial(self):
        t = tree(self.ski)
        cid = ess_v2(signer_info(t))[0][1]
        iss = [x for x in cid if x[0] == 0x30 and x[1][0][0] == 0x30]
        self.assertEqual(len(iss), 1, "openssl -cades writes issuerSerial")
        serial = iss[0][1][1]
        serial[1] = serial[1][:-1] + bytes([serial[1][-1] ^ 1])
        self.assertIn("issuerSerial", self.anchor(enc(t)))

    def test_ess_issuer_name(self):
        t = tree(self.ski)
        cid = ess_v2(signer_info(t))[0][1]
        names = [x for x in cid if x[0] == 0x30 and x[1][0][0] == 0x30][0][1][0]
        rdn = names[1][0][1][0][1][-1][1][0][1][1]                       # [4] directoryName / Name / last RDN's value
        rdn[1] = rdn[1][:-1] + b"X"
        self.assertIn("issuerSerial", self.anchor(enc(t)))

    def test_attribute_with_two_values(self):
        t = tree(self.ski)
        for a in signer_info(t)[1][3][1]:
            if TA._oid_of(a[1][0][1]) == TA._OID_SIGNING_CERTIFICATE_V2:
                a[1][1][1].append(copy.deepcopy(a[1][1][1][0]))
        self.assertIn("not exactly one value", self.anchor(enc(t)))

    def test_more_than_one_ess_cert_id(self):
        t = tree(self.ski)
        ids = ess_v2(signer_info(t))
        ids.append(copy.deepcopy(ids[0]))
        # 0.13.0 (spec §5 step 8): more than one ESSCertID is read; a certificate listed twice is refused
        self.assertIn("the same certificate hash as an earlier ESSCertID", self.anchor(enc(t)))

    def to_key_id(self, tok):
        """the tree of an issuerAndSerialNumber token with its sid rewritten to the TSA's key identifier"""
        t = tree(tok)
        signer_info(t)[1][1] = [0x80, ski_of(self.lab.j("tsa.crt"))]
        return enc(t)

    def test_ess_v1_with_sha1(self):
        """signingCertificate (RFC 2634, SHA-1), as openssl ts -reply writes it with ess_cert_id_alg = sha1"""
        self.lab.ess_alg = "sha1"
        try:
            tok = self.to_key_id(self.lab.token(self.imp))
        finally:
            self.lab.ess_alg = "sha256"
        self.assertIsNone(self.anchor(tok))
        t = tree(tok)
        for a in signer_info(t)[1][3][1]:
            if TA._oid_of(a[1][0][1]) == TA._OID_SIGNING_CERTIFICATE:
                h = a[1][1][1][0][1][0][1][0][1][0]
                h[1] = bytes([h[1][0] ^ 1]) + h[1][1:]
        self.assertIn("certHash", self.anchor(enc(t)))

    def test_ess_chain_of_ids(self):
        """ess_cert_id_chain = yes: two ESSCertIDs (signer, then its CA). 0.13.0 (spec §5 step 8, RFC 2634 §5.4): the
        first is the signer, the second limits the path; accepted (0.12.0 refused "2 ESSCertIDs")"""
        tok = self.lab.token(self.imp, chain=True)
        self.assertIsNone(self.anchor(self.to_key_id(tok)))

    def test_ess_v2_hash_algorithm(self):
        """ESSCertIDv2 with an explicit hashAlgorithm (sha384): accepted; with a parameter that is not NULL: refused"""
        self.lab.ess_alg = "sha384"
        try:
            tok = self.to_key_id(self.lab.token(self.imp))
        finally:
            self.lab.ess_alg = "sha256"
        self.assertIsNone(self.anchor(tok))
        t = tree(tok)
        ai = ess_v2(signer_info(t))[0][1][0]
        self.assertEqual((ai[0], len(ai[1])), (0x30, 1))
        ai[1].append([0x02, b"\x01"])
        self.assertIn("hash algorithm", self.anchor(enc(t)))
        ai[1][1] = [0x05, b""]                                            # a NULL parameter is accepted
        self.assertIsNone(self.anchor(enc(t)))

    def test_tsa_field_in_subject_alt_name(self):
        san = Lab(self.td, "san", tsa_ext="v3_tsa_san")
        leaf = first_der(san.j("tsa.crt"))
        pins = TA._pins_pem([san.ca])
        base = san.resign(san.token(self.imp))
        now = int(time.time()) + 1
        self.assertIsNone(self.anchor(base, pins=pins, leaf=leaf, at=now))
        for name, ok in ((b"tsa.example", True), (b"other.example", False)):
            t = tree(base)
            econtent = t[1][1][1][0][1][2][1][1][1][0]                  # SignedData / encapContentInfo / [0] / OCTET STRING
            tst = tree(econtent[1])
            tst[1].append([0xA0, [[0x82, name]]])                        # tsa [0] GeneralName dNSName
            econtent[1] = enc(tst)
            why = self.anchor(enc(t), pins=pins, leaf=leaf, at=now)
            self.assertEqual(why is None, ok, why)

    @unittest.skipUnless(HAVE_CRYPTOGRAPHY, "needs `cryptography` (the `sign` extra) to build the names")
    def test_names_compared_as_openssl(self):
        """the tsa field and the ESS issuerSerial name are compared as X509_NAME_cmp compares names"""
        from cryptography import x509
        from cryptography.x509.name import _ASN1Type
        from cryptography.x509.oid import NameOID
        with open(self.lab.j("tsa.crt"), "rb") as f:
            cn = x509.load_pem_x509_certificate(f.read()).subject.rfc4514_string()[3:]

        def with_tsa(name):
            t = tree(self.ski)
            econtent = t[1][1][1][0][1][2][1][1][1][0]
            tst = tree(econtent[1])
            tst[1].append([0xA0, [[0xA4, [tree(name.public_bytes())]]]])
            econtent[1] = enc(tst)
            return enc(t)
        for value, typ, ok in ((cn, None, True), (cn.upper(), None, True), ("  " + cn + " ", None, True),
                               (cn, _ASN1Type.PrintableString, True), (cn.replace("-", " - "), None, False),
                               (cn + "x", None, False)):
            attr = x509.NameAttribute(NameOID.COMMON_NAME, value, typ) if typ else x509.NameAttribute(NameOID.COMMON_NAME, value)
            why = self.anchor(with_tsa(x509.Name([attr])))
            self.assertEqual(why is None, ok, (value, typ, why))
        t = tree(self.ski)                                                # the issuerSerial name in other case
        cid = ess_v2(signer_info(t))[0][1]
        name = [x for x in cid if x[0] == 0x30 and x[1][0][0] == 0x30][0][1][0][1][0][1][0]
        rdn = name[1][-1][1][0][1][1]
        rdn[1] = rdn[1].upper()
        self.assertIsNone(self.anchor(enc(t)))
        N, A_ = x509.Name, x509.NameAttribute
        self.assertTrue(TA._names_equal(N([A_(NameOID.COMMON_NAME, "A\tB")]).public_bytes(),
                                        N([A_(NameOID.COMMON_NAME, "a b")]).public_bytes()))
        self.assertFalse(TA._names_equal(b"\x30\x00", b"\x31\x00"))      # not a Name: never equal
        cn_o = N([A_(NameOID.COMMON_NAME, "x"), A_(NameOID.ORGANIZATION_NAME, "y")]).public_bytes()
        o_cn = N([A_(NameOID.ORGANIZATION_NAME, "y"), A_(NameOID.COMMON_NAME, "x")]).public_bytes()
        self.assertFalse(TA._names_equal(cn_o, o_cn))                     # RDNs in order
        multi = N([x509.RelativeDistinguishedName([A_(NameOID.COMMON_NAME, "x"), A_(NameOID.ORGANIZATION_NAME, "y")])])
        atv = [enc(x) for x in tree(multi.public_bytes())[1][0][1]]       # the two attributes of the RDN, swapped by hand
        swapped = der(0x30, der(0x31, atv[1] + atv[0]))
        self.assertNotEqual(swapped, multi.public_bytes())
        self.assertTrue(TA._names_equal(swapped, multi.public_bytes()))   # one RDN: any order
        self.assertFalse(TA._names_equal(N([A_(NameOID.COMMON_NAME, "É")]).public_bytes(),
                                         N([A_(NameOID.COMMON_NAME, "é")]).public_bytes()))   # ASCII letters only
        self.assertFalse(TA._names_equal(N([A_(NameOID.COMMON_NAME, "x")]).public_bytes(),
                                         N([A_(NameOID.ORGANIZATION_NAME, "x")]).public_bytes()))   # the OID counts
        self.assertFalse(TA._general_names_equal((0x82, cn_o), (0xA4, cn_o)))    # the GeneralName type counts
        self.assertTrue(TA._general_names_equal((0x82, b"tsa.example"), (0x82, b"tsa.example")))
        self.assertFalse(TA._general_names_equal((0x82, b"tsa.example"), (0x82, b"TSA.example")))   # bytes, not a Name

    def test_signer_info_without_signed_attributes(self):
        t = tree(self.ski)
        si = signer_info(t)
        self.assertEqual(si[1][3][0], 0xA0)
        del si[1][3]
        self.assertEqual(self.anchor(enc(t)), "the SignerInfo has no signed attributes")

    def test_oid_arc_not_minimal(self):
        v2 = bytes.fromhex("2a864886f70d010910022f")                     # 1.2.840.113549.1.9.16.2.47
        self.assertEqual(TA._oid_of(v2), TA._OID_SIGNING_CERTIFICATE_V2)
        for bad in (b"\x80" + v2, v2[:1] + b"\x80" + v2[1:]):           # a leading 0x80 in the first or a later arc
            with self.assertRaises(TA.TokenRefused):
                TA._oid_of(bad)

    def test_tsa_field_with_two_names(self):
        """the tsa field is one GeneralName: two, the first the signer's subject, are refused"""
        cert = TA._items(TA._one(self.leaf, 0x30))
        tbs = TA._items(cert[0][1])
        k = 1 if tbs[0][0] == 0xA0 else 0
        subject = tree(TA._tlv(0x30, tbs[k + 4][1]))
        for names, ok in (([[0xA4, [subject]]], True), ([[0xA4, [subject]], [0x82, b"x.example"]], False)):
            t = tree(self.ski)
            econtent = t[1][1][1][0][1][2][1][1][1][0]
            tst = tree(econtent[1])
            tst[1].append([0xA0, copy.deepcopy(names)])
            econtent[1] = enc(tst)
            why = self.anchor(enc(t))
            self.assertEqual(why is None, ok, why)

    def test_validity_at_gen_time(self):
        self.assertIsNotNone(self.anchor(self.ski, at=self.at + 10 * 86400))   # certificates of 2 days
        self.assertIsNotNone(self.anchor(self.ski, at=self.at - 10 * 86400))

    def test_pinned_leaf_and_the_ca_in_the_token(self):
        """a pinned leaf does not end the chain: the CA the token carries is checked too, as ts -verify does for the
        other form of the same token (both refuse a CA without keyCertSign)"""
        bad = Lab(self.td, "badca", ca_ext="v3_badca")
        tok = bad.token(self.imp)
        leaf = first_der(bad.j("tsa.crt"))
        p = os.path.join(self.td, "bad.der")
        with open(p, "wb") as f:
            f.write(tok)
        r = subprocess.run(["openssl", "ts", "-verify", "-token_in", "-in", p, "-digest", self.imp, "-CAfile",
                            bad.j("tsa.crt"), "-untrusted", bad.j("tsa.crt"), "-partial_chain"], capture_output=True)
        mine = self.anchor(bad.resign(tok), pins=TA._pins_pem([bad.j("tsa.crt")]), leaf=leaf)
        self.assertEqual(r.returncode == 0, mine is None, (r.stderr[-200:], mine))
        self.assertIsNotNone(mine)
        self.assertIsNone(self.anchor(self.ski, pins=TA._pins_pem([self.lab.j("tsa.crt")])))   # control: leaf pinned


def _nodes(n, path=()):
    """every node of a tree with its path"""
    yield path, n
    if isinstance(n[1], list):
        for i, c in enumerate(n[1]):
            yield from _nodes(c, path + (i,))


def _at(t, path):
    for i in path:
        t = t[1][i]
    return t


@NEEDS
class Generative(unittest.TestCase):
    """every DER element of the key-identified token changed in five ways (dropped, duplicated, retagged, a stranger
    appended inside, its value flipped or emptied): the step answers a reason or None, never raises; every change inside
    the ESS attribute, or of the tsa field to a name that is not the signer's, is refused; and through the public
    function (token re-hashed and record re-signed, so the change reaches step 8) the answer is a bool with a closed reason"""

    @classmethod
    def setUpClass(cls):
        cls.td = tempfile.mkdtemp()
        cls.lab = Lab(cls.td, "a")
        cls.leaf = first_der(cls.lab.j("tsa.crt"))
        cls.pins = TA._pins_pem([cls.lab.ca])
        cls.lte = sealed(cls.lab)
        cls.ski = base64.b64decode(cls.lte.records[0]["token_b64"])
        cls.at = int(time.time())

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.td, ignore_errors=True)

    def variants(self):
        base = tree(self.ski)
        for path, _n in list(_nodes(base)):
            if not path:
                continue
            for how in ("drop", "dup", "retag", "stranger", "flip"):
                t = copy.deepcopy(base)
                parent, i = _at(t, path[:-1]), path[-1]
                node = parent[1][i]
                if how == "drop":
                    del parent[1][i]
                elif how == "dup":
                    parent[1].insert(i, copy.deepcopy(node))
                elif how == "retag":                     # a constructed element becomes an OCTET STRING of its content
                    content = b"".join(enc(c) for c in node[1]) if isinstance(node[1], list) else node[1]
                    parent[1][i] = [0x04 if node[0] != 0x04 else 0x0C, content]
                elif how == "stranger":
                    if not isinstance(node[1], list):
                        continue
                    node[1].append([0x8A, b"\x01"])
                elif how == "flip":
                    if isinstance(node[1], list):
                        continue
                    node[1] = bytes([node[1][0] ^ 0x01]) + node[1][1:] if node[1] else b"\x00"
                yield path, how, enc(t)

    def test_the_step_never_raises(self):
        self.assertIsNone(TA._key_id_anchor(self.ski, self.leaf, self.pins, self.at, self.td))
        ess_path = None
        base = tree(self.ski)
        si = signer_info(base)
        for k, a in enumerate(si[1][3][1]):
            if TA._oid_of(a[1][0][1]) == TA._OID_SIGNING_CERTIFICATE_V2:
                ess_path = (1, 0, len(base[1][1][1][0][1]) - 1, 0, 3, k)   # [0] / SignedData / signerInfos / SI / attrs / k
        self.assertIs(_at(base, ess_path), si[1][3][1][ess_path[-1]])
        n = refused = 0
        accepted = []
        for path, how, tok in self.variants():
            why = TA._key_id_anchor(tok, self.leaf, self.pins, self.at, self.td)
            self.assertTrue(why is None or isinstance(why, str), (path, how, why))
            n += 1
            if path[:len(ess_path)] == ess_path and (path, how) != (ess_path + (1, 0, 0, 0, 1), "drop"):
                # the ESS attribute or anything inside it; dropping the ESSCertIDv2's issuerSerial (OPTIONAL, RFC 5035)
                # leaves a valid attribute, accepted here and caught by the CMS signature at step 7
                if why is None:
                    accepted.append((path, how))
                refused += why is not None
        self.assertEqual(accepted, [])
        self.assertGreater(n, 400)
        self.assertGreater(refused, 40)

    def test_through_the_public_function(self):
        ok0, log0 = answer(self.lte, [self.lab.ca])
        self.assertEqual(ok0, [True], log0)                              # control
        rnd = random.Random(20261117)
        cases = list(self.variants())
        rnd.shuffle(cases)
        seen = set()
        for path, how, tok in cases[:150]:
            lte = LongTermEvidence(D, records=copy.deepcopy(self.lte.records))
            r = lte.records[0]
            r["token_b64"] = base64.b64encode(tok).decode()
            r["token_sha3"] = hashlib.sha3_256(r["token_b64"].encode()).hexdigest()
            r["sig"] = lte._msg(0, r, r.get("hash", "sha3-256")).hex()
            fn = TA.make_timestamp_trust_fn(lte, [self.lab.ca])
            ok = fn(r)
            self.assertIsInstance(ok, bool)
            self.assertIn(fn.log[-1]["reason"], (None,) + TA.REASONS, (path, how))
            seen.add(fn.log[-1]["reason"])
        self.assertIn("not_issued_by_pinned_tsa", seen)   # mutations reached step 8
        self.assertIn("signature_invalid", seen)


if __name__ == "__main__":
    unittest.main()
