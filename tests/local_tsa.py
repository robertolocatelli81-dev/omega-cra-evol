# SPDX-License-Identifier: AGPL-3.0-or-later
"""A TSA of this machine for the tests (openssl ts -reply): real RFC 3161 tokens under a CA made on the spot, no trust
attached. The same construction as cryptovalid-opencore's verifiers/pack_states_bench.LocalTsa (same author), with
SHA3-256 queries allowed too."""
import base64
import os
import shutil
import subprocess

HAVE_OPENSSL = shutil.which("openssl") is not None

_CNF = ("[ tsa ]\ndefault_tsa = t1\n[ t1 ]\nserial = {d}/serial\ncrypto_device = builtin\nsigner_cert = {d}/tsa.crt\n"
        "certs = {d}/ca.crt\nsigner_key = {d}/tsa.key\nsigner_digest = sha256\ndefault_policy = 1.2.3.4.1\n"
        "digests = sha256, sha3-256\naccuracy = secs:1\nordering = yes\ntsa_name = no\ness_cert_id_chain = no\n"
        "ess_cert_id_alg = sha256\n[ v3_tsa ]\nextendedKeyUsage = critical,timeStamping\nbasicConstraints = CA:FALSE\n")


def _run(*a):
    subprocess.run(list(a), check=True, capture_output=True, timeout=60)


class LocalTsa:
    def __init__(self, td):
        self.td = td
        os.makedirs(td, exist_ok=True)
        j = self.j
        with open(j("tsa.cnf"), "w") as f:
            f.write(_CNF.format(d=td))
        with open(j("serial"), "w") as f:
            f.write("01\n")
        _run("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout",
             j("ca.key"), "-out", j("ca.crt"), "-subj", "/CN=test-ca", "-days", "2")
        _run("openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", j("tsa.key"),
             "-out", j("tsa.csr"), "-subj", "/CN=test-tsa")
        _run("openssl", "x509", "-req", "-in", j("tsa.csr"), "-CA", j("ca.crt"), "-CAkey", j("ca.key"), "-CAcreateserial",
             "-out", j("tsa.crt"), "-days", "2", "-extfile", j("tsa.cnf"), "-extensions", "v3_tsa")

    def j(self, n):
        return os.path.join(self.td, n)

    @property
    def ca(self):
        return self.j("ca.crt")

    def token(self, digest_hex, alg="sha256", token_only=False):
        """base64 of a granted TimeStampResp (or of the token alone) over `digest_hex` hashed with `alg`"""
        _run("openssl", "ts", "-query", "-digest", digest_hex, "-" + alg, "-cert", "-out", self.j("q.tsq"))
        _run("openssl", "ts", "-reply", "-queryfile", self.j("q.tsq"), "-config", self.j("tsa.cnf"), "-section", "t1",
             "-out", self.j("r.tsr"))
        out = self.j("r.tsr")
        if token_only:
            _run("openssl", "ts", "-reply", "-in", out, "-token_out", "-out", self.j("t.der"))
            out = self.j("t.der")
        with open(out, "rb") as f:
            return base64.b64encode(f.read()).decode()
