"""A secret given to this package does not come out of it (0.13.2, CHANGELOG; the class found on 25-26/11/2026 in
ap2-evidence-pack 1.11.2 and cryptovalid-opencore 0.29.1, same author).

The inputs that take a secret, found by `grep` on the sources (TheInputs keeps the list): the seed files of `--key`
(sign, attest) and `--tip-key` (every command with a ledger, seal), the seed `keygen` writes, `--aws-creds-file`, the
variables AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN / AWS_KMS_ENDPOINT, the arguments of KMSSigner,
the names of a trust store (`--trust-store` of verify and verify-attestation: a key put where a name goes) and the
private key of a long-term Signer, ephemeral or given. A canary goes into each, and is searched in everything that comes
out: standard output and error, every file written, the exception, the environment and argv of the one child process
(openssl). It is searched raw and in hex, HEX, decimal, base64 and base64url at each of the three offsets (inside a
longer text too). Method and search from agent-payment-chain tests/test_secrets.py (same author, AGPL-3.0-or-later).

Positive control: the search finds a producer that leaks in each form; and on 0.13.1 (and 0.12.0) the tests that state
the new behaviour fail."""
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import traceback
import types
import unittest
from unittest import mock

from omega_cra_evol import kms, longterm, time_anchor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKG = os.path.join(ROOT, "omega_cra_evol")
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: F401
    HAVE = True
except ImportError:   # pragma: no cover - the [sign] extra is absent
    HAVE = False

SEED = hashlib.sha256(b"cra test_secrets canary seed").digest()           # a test key, not anyone's
AK = "AKIA" + base64.b32encode(hashlib.sha256(b"ak").digest()).decode()[:16]
SK = base64.b64encode(hashlib.sha256(b"sk").digest()).decode()[:40]
ST = "IQo" + base64.b64encode(hashlib.sha256(b"st").digest() * 2).decode()
PW = "Pw" + base64.urlsafe_b64encode(hashlib.sha256(b"pw").digest()).decode()[:30]
KEYNAME = base64.urlsafe_b64encode(SEED).decode().rstrip("=")             # 43 characters: a key put where a name goes
CANARIES = (SEED, SEED.hex().encode(), AK.encode(), SK.encode(), ST.encode(), PW.encode(), KEYNAME.encode())
PY = [sys.executable, "-B", "-m", "omega_cra_evol.cli"]
DEAD = "http://127.0.0.1:1"            # loopback, nothing listens: the request fails before any answer


def forms(secret):
    out = {"raw": secret, "hex": secret.hex().encode(), "HEX": secret.hex().upper().encode(),
           "decimal": str(int.from_bytes(secret, "big")).encode()}
    for k in range(3):          # base64 of the secret inside a longer text: what depends on the secret alone, at each offset
        whole = base64.b64encode(b"\0" * k + secret + b"\0" * ((3 - (k + len(secret)) % 3) % 3))
        part = whole[(k * 8 + 5) // 6:(k + len(secret)) * 8 // 6]
        out["base64+%d" % k], out["base64url+%d" % k] = part, part.replace(b"+", b"-").replace(b"/", b"_")
    return out


def found(secret, *outputs):
    blob = b"\n".join(o if isinstance(o, bytes) else str(o).encode("utf-8", "surrogatepass") for o in outputs)
    blob += b"\n" + blob.replace(b"\\/", b"/")      # JSON may escape the slash of base64
    return sorted(n for n, f in forms(secret).items() if f in blob)


class Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="crasec-")
        self.addCleanup(shutil.rmtree, self.d, True)
        self.home = os.path.join(self.d, "home")
        os.mkdir(self.home)

    def file(self, name, data):
        p = os.path.join(self.d, name)
        with open(p, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode())
        return p

    def left(self, inputs=()):
        """Every file of the folder but the inputs (which hold a canary by construction)."""
        out = []
        for base, _, files in os.walk(self.d):
            for n in files:
                p = os.path.join(base, n)
                if os.path.abspath(p) in [os.path.abspath(i) for i in inputs]:
                    continue
                with open(p, "rb") as f:
                    out.append(f.read())
        return out

    def none(self, what, *outputs, inputs=()):
        for c in CANARIES:
            self.assertEqual(found(c, *outputs, *self.left(inputs)), [], "%s: %r" % (what, c[:8]))

    def cli(self, *argv, env=None):
        e = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}
        e.update(HOME=self.home, USERPROFILE=self.home, PYTHONPATH=ROOT + os.pathsep + os.environ.get("PYTHONPATH", ""))
        e.update(env or {})
        return subprocess.run(PY + list(argv), capture_output=True, timeout=120, cwd=self.d, env=e)

    def seedfile(self):
        return self.file("seed.key", SEED.hex())

    def ledger_and_pack(self, tip_key=None):
        led, pack = os.path.join(self.d, "l.jsonl"), os.path.join(self.d, "p.json")
        extra = ["--tip-key", tip_key] if tip_key else []
        r = self.cli("sbom", "--ledger", led, "--product", "p", "--version", "1", "--installed", "pip", *extra)
        self.assertEqual(r.returncode, 0, r.stderr)
        r2 = self.cli("pack", "--ledger", led, "--product", "p", "--version", "1", "--out", pack, *extra)
        self.assertEqual(r2.returncode, 0, r2.stderr)
        return led, pack, r.stdout + r.stderr + r2.stdout + r2.stderr


class TheSearchFinds(Base):
    """Positive control of the search, and of a producer that leaks."""

    def test_every_form(self):
        s = SEED
        for name, text in (("raw", b"x" + s + b"y"), ("hex", b'"' + s.hex().encode()), ("HEX", s.hex().upper().encode()),
                           ("decimal", str(int.from_bytes(s, "big")).encode()), ("base64+0", base64.b64encode(s)),
                           ("base64+1", base64.b64encode(b"{" + s + b"}")), ("base64+2", base64.b64encode(b'{"' + s)),
                           ("base64url+0", base64.urlsafe_b64encode(s)), ("base64url+1", base64.urlsafe_b64encode(b"a" + s)),
                           ("base64url+2", base64.urlsafe_b64encode(b"ab" + s + b"c"))):
            self.assertIn(name, found(s, text), name)
        self.assertEqual(found(s, b"nothing", hashlib.sha256(s).hexdigest()), [])

    def test_a_producer_that_leaks_is_found(self):
        r = subprocess.run([sys.executable, "-c", "import sys; sys.stderr.write(sys.argv[1])", SK], capture_output=True, timeout=60)
        with self.assertRaises(AssertionError):
            self.none("a leak on stderr", r.stderr)
        self.file("leak.txt", base64.b64encode(b"ab" + SEED))
        with self.assertRaises(AssertionError):
            self.none("a leak in a file")


class TheInputs(unittest.TestCase):
    """The census is the sources': a new way in for a secret makes this list change, and this file with it."""

    def read(self, name):
        with open(os.path.join(PKG, name), encoding="utf-8") as f:
            return f.read()

    def test_the_environment_read(self):
        names = set()
        for n in sorted(os.listdir(PKG)):
            if n.endswith(".py"):
                t = self.read(n)
                for marker in ('environ.get("', "getenv(\""):
                    i = t.find(marker)
                    while i >= 0:
                        names.add(t[i + len(marker):t.index('"', i + len(marker))])
                        i = t.find(marker, i + 1)
        self.assertEqual(names,
                         {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_KMS_ENDPOINT"})

    def test_the_options_that_take_a_secret(self):
        cli = self.read("cli.py")
        for opt in ("--key", "--tip-key", "--aws-creds-file", "--aws-kms-key-id", "--trust-store"):
            self.assertIn('"%s"' % opt, cli)
        self.assertEqual(sorted(o for o in ("--password", "--pin", "--token", "--secret", "--passphrase") if '"%s"' % o in cli), [])

    def test_one_child_process(self):
        hits = [n for n in sorted(os.listdir(PKG)) if n.endswith(".py") and
                any(w in self.read(n) for w in ("subprocess.run(", "Popen(", "os.system(", "os.exec", "os.spawn"))]
        self.assertEqual(hits, ["time_anchor.py"])
        self.assertEqual(self.read("time_anchor.py").count("subprocess.run("), 1)


@unittest.skipUnless(HAVE, "the [sign] extra (cryptography) is not installed")
class SeedFiles(Base):
    def test_keygen_prints_no_seed(self):
        p = os.path.join(self.d, "new.key")
        r = self.cli("keygen", p)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(p, encoding="utf-8") as f:
            seed = bytes.fromhex(f.read().strip())
        for c in (seed, seed.hex().encode()):
            self.assertEqual(found(c, r.stdout, r.stderr), [])

    def test_sign_and_tip_write_no_seed(self):
        key = self.seedfile()
        led, pack, out = self.ledger_and_pack(tip_key=key)
        r = self.cli("sign", pack, "--key", key, "--signer-id", "me")
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(pack, encoding="utf-8") as f:
            digest = json.load(f)["pack_sha3"]
        r2 = self.cli("seal", "--ledger", led, "--product", "p", "--version", "1", "--pack-sha3", digest, "--tip-key", key)
        self.assertEqual(r2.returncode, 0, r2.stderr)
        r3 = self.cli("seal", "--ledger", led, "--product", "p", "--version", "1", "--pack-sha3", digest,
                      "--tip-key", key, "--print-imprint")
        self.assertEqual(r3.returncode, 0, r3.stderr)
        self.none("sign, tip, seal", out, r.stdout, r.stderr, r2.stdout, r2.stderr, r3.stdout, r3.stderr, inputs=(key,))

    def test_a_seed_given_in_place_of_its_file_is_not_repeated(self):
        led, pack, _ = self.ledger_and_pack()
        h = SEED.hex()
        for argv in (("sign", pack, "--key", h, "--signer-id", "me"),
                     ("attest", pack, "--ledger", led, "--key", h, "--signer-id", "me", "--out", os.path.join(self.d, "o")),
                     ("sbom", "--ledger", led, "--product", "p", "--version", "1", "--installed", "pip", "--tip-key", h),
                     ("seal", "--ledger", led, "--product", "p", "--version", "1", "--pack-sha3", "ab" * 32, "--tip-key", h),
                     ("sign", pack, "--aws-kms-key-id", "k", "--aws-region", "eu-west-1", "--aws-creds-file", SK, "--signer-id", "x")):
            r = self.cli(*argv)
            self.assertNotEqual(r.returncode, 0, argv)
            self.none(argv[0], r.stdout, r.stderr)

    def test_a_secret_in_place_of_an_argument_is_not_repeated(self):
        for argv in (("keygen", os.path.join(self.d, "k"), SEED.hex()), ("verify", "p.json", SK),
                     ("schema", "--stream", SEED.hex()), ("verify", "p.json", "--log-pubkey", KEYNAME)):
            r = self.cli(*argv)
            self.assertEqual(r.returncode, 2, (argv, r.stderr))
            self.none(argv[0], r.stdout, r.stderr)

    def test_the_bound_of_a_repeated_argument(self):
        longpath = self.file("f" * 45 + ".json", "{}")
        for arg, shown in (("a" * 39, True), ("a" * 40, False), (longpath, True), (os.path.join(self.d, "nofolder", "g" * 45), False)):
            r = self.cli("verify", "p.json", arg)
            self.assertEqual(r.returncode, 2)
            self.assertEqual(arg.encode() in r.stderr, shown, arg)
            self.assertEqual(b"characters not repeated" in r.stderr, not shown, arg)

    def test_a_bad_seed_file_shows_no_content(self):
        for body in (SEED.hex() + "zz", SEED.hex() + "00", b"\xff" + SEED, SEED.hex()[:-2]):
            key = self.file("bad.key", body)
            r = self.cli("sbom", "--ledger", os.path.join(self.d, "l2.jsonl"), "--product", "p", "--version", "1",
                         "--installed", "pip", "--tip-key", key)
            self.assertNotEqual(r.returncode, 0, body)
            self.none("bad seed", r.stdout, r.stderr, inputs=(key,))

    def test_a_seal_holds_no_private_key(self):
        from omega_cra_evol.signing import load_key
        for given in (None, load_key(self.seedfile())):           # ephemeral, and the identity of --tip-key
            s = longterm.Signer("ed25519", key=given)
            lte = longterm.LongTermEvidence("ab" * 32)
            lte.seal(s, 1700000000.0)
            from cryptography.hazmat.primitives import serialization as ser
            raw = s._sk.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption())
            self.assertEqual(found(raw, json.dumps(lte.to_dict()), repr(lte.records)), [])


class KMS(Base):
    URLS = ("https://u:%s@kms.example/" % PW, "https://%s@kms.example/" % PW, "HTTPS://u:%s@kms.example" % PW,
            "http://u:%s@127.0.0.1:1/" % PW, "http://%s:@localhost:1/" % PW, "https://%s:x@[::1]:1/" % PW)

    def test_a_url_with_user_information_is_refused_before_the_network(self):
        class Reached(Exception):
            pass

        def reached(*a):
            raise Reached()
        for url in self.URLS:
            with mock.patch.object(kms.urllib.request, "build_opener", side_effect=reached):
                with self.assertRaises(ValueError, msg=url) as cm:
                    kms.KMSSigner("k", "eu-west-1", AK, SK, ST, endpoint=url)
            self.none(url, str(cm.exception), repr(cm.exception))

    def test_the_cli_too(self):
        _, pack, _ = self.ledger_and_pack()
        for url in self.URLS[:2]:
            r = self.cli("sign", pack, "--aws-kms-key-id", "k", "--aws-region", "eu-west-1", "--signer-id", "x",
                         env={"AWS_KMS_ENDPOINT": url, "AWS_ACCESS_KEY_ID": AK, "AWS_SECRET_ACCESS_KEY": SK, "AWS_SESSION_TOKEN": ST})
            self.assertNotEqual(r.returncode, 0)
            self.none(url, r.stdout, r.stderr)

    def test_a_network_error_says_its_kind_not_its_text(self):
        class Err(OSError):
            pass
        boom = Err(111, "refused " + PW + " " + SK)
        with mock.patch.object(kms.urllib.request.OpenerDirector, "open", side_effect=boom):
            with self.assertRaises(OSError) as cm:
                kms.KMSSigner("k", "eu-west-1", AK, SK, ST, endpoint=DEAD)
        tb = "".join(traceback.format_exception(type(cm.exception), cm.exception, cm.exception.__traceback__))
        self.none("network error", str(cm.exception), repr(cm.exception), repr(cm.exception.args), tb)
        self.assertIn("Err", str(cm.exception))
        self.assertEqual(cm.exception.errno, 111)

    def test_credentials_from_file_and_environment_never_come_out(self):
        led, pack, _ = self.ledger_and_pack()
        creds = self.file("creds.env", "AWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\nAWS_SESSION_TOKEN=%s\n" % (AK, SK, ST))
        aws = {"AWS_KMS_ENDPOINT": DEAD}
        runs = [self.cli("sign", pack, "--aws-kms-key-id", "k", "--aws-region", "eu-west-1", "--signer-id", "x",
                         "--aws-creds-file", creds, env=aws),
                self.cli("sign", pack, "--aws-kms-key-id", "k", "--aws-region", "eu-west-1", "--signer-id", "x",
                         env=dict(aws, AWS_ACCESS_KEY_ID=AK, AWS_SECRET_ACCESS_KEY=SK, AWS_SESSION_TOKEN=ST)),
                self.cli("attest", pack, "--ledger", led, "--aws-kms-key-id", "k", "--aws-region", "eu-west-1",
                         "--signer-id", "x", "--out", os.path.join(self.d, "o"), "--aws-creds-file", creds, env=aws)]
        for r in runs:
            self.assertNotEqual(r.returncode, 0)
            self.none("kms", r.stdout, r.stderr, inputs=(creds,))

    def test_no_credential_reaches_the_child_process(self):
        seen = []

        def run(argv, *a, **k):
            seen.append((list(argv), dict(k.get("env") if k.get("env") is not None else os.environ)))
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        fake = types.SimpleNamespace(run=run, TimeoutExpired=subprocess.TimeoutExpired, CompletedProcess=subprocess.CompletedProcess)
        env = {"AWS_ACCESS_KEY_ID": AK, "AWS_SECRET_ACCESS_KEY": SK, "AWS_SESSION_TOKEN": ST,
               "AWS_KMS_ENDPOINT": "https://u:%s@h/" % PW}
        with mock.patch.dict(os.environ, env), mock.patch.object(time_anchor, "subprocess", fake), \
                mock.patch.object(time_anchor.shutil, "which", return_value=sys.executable):
            time_anchor._openssl(["version"], 5)
        self.assertEqual(len(seen), 1)
        argv, child = seen[0]
        self.assertEqual(sorted(set(child) & set(env)), [])
        self.assertIn("PATH", {k.upper() for k in child})        # the child still finds its libraries and configuration
        self.none("child", " ".join(argv), json.dumps(child))


@unittest.skipUnless(HAVE, "the [sign] extra (cryptography) is not installed")
class TrustStoreNames(Base):
    """A name of more than 32 characters (a key put in its place) is named by its length."""

    def stores(self):
        pub = "11" * 32
        return ['{"%s": "zz"}' % KEYNAME, '{"%s": 1}' % KEYNAME, '{"%s": "%s", "%s": "%s"}' % (KEYNAME, pub, KEYNAME, pub),
                '{"%s": "%s"}' % (KEYNAME, "00" * 32)]

    def test_verify_and_verify_attestation(self):
        from omega_cra_evol.art14_attest import sign_envelope
        from omega_cra_evol.signing import load_key
        _, pack, _ = self.ledger_and_pack()
        seed = self.seedfile()
        env = self.file("e.json", json.dumps(sign_envelope(b"{}", load_key(seed), "me")))
        for doc in self.stores():
            ts = self.file("ts.json", doc)
            for argv in (("verify", pack, "--trust-store", ts), ("verify-attestation", env, "--trust-store", ts)):
                r = self.cli(*argv)
                self.assertNotEqual(r.returncode, 0, (argv, doc))
                self.none(doc, r.stdout, r.stderr, inputs=(ts, seed))

    def test_32_repeated_33_not(self):
        from omega_cra_evol.art14_attest import sign_envelope, verify_envelope
        from omega_cra_evol.signing import load_key
        env = self.file("e.json", json.dumps(sign_envelope(b"{}", load_key(self.seedfile()), "me")))
        for n in (32, 33, 300):
            name = "S" * n
            r = json.dumps(verify_envelope(env, {name: "zz"}))
            self.assertEqual(name in r, n <= 32, n)
            self.assertEqual(("%d characters" % n) in r, n > 32, n)


if __name__ == "__main__":
    unittest.main()
