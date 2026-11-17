# SPDX-License-Identifier: AGPL-3.0-or-later
"""NIST IR 8547 (final, October 2026), §4.1.1 Table 2: EdDSA "Deprecated after 2030", "Disallowed after 2035". The same
section says SP 800-57 had projected disallowing 112-bit schemes "on January 1, 2031" and that NIST "will instead
deprecate ... after 2030": "after 2030" is from 2031-01-01T00:00:00Z, "after 2035" from 2036-01-01T00:00:00Z.

Until 0.13.0 the constants were 2030-01-01 and 2035-01-01, one year earlier. Positive control (17/11/2026): on the code
of v0.12.0 the tests at the 2035/2036 boundaries fail (an Ed25519 seal was refused for the whole of 2035). Each
boundary is checked one day before, at the instant and one day after, on the policy and through `verify` and
`renewal_due`."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from omega_cra_evol.longterm import (NIST_IR_8547_DEPRECATED_AFTER, NIST_IR_8547_DISALLOWED_AFTER,  # noqa: E402
                                     AlgorithmPolicy, LongTermEvidence, Signer)

DAY = 86400.0
Y2031 = 1924992000.0   # 2031-01-01T00:00:00Z
Y2036 = 2082758400.0   # 2036-01-01T00:00:00Z
try:
    import cryptography  # noqa: F401
    HAVE_CRYPTOGRAPHY = True
except ImportError:
    HAVE_CRYPTOGRAPHY = False


class Constants(unittest.TestCase):
    def test_the_instants_of_the_final_text(self):
        from datetime import datetime, timezone
        self.assertEqual(NIST_IR_8547_DEPRECATED_AFTER, datetime(2031, 1, 1, tzinfo=timezone.utc).timestamp())
        self.assertEqual(NIST_IR_8547_DISALLOWED_AFTER, datetime(2036, 1, 1, tzinfo=timezone.utc).timestamp())
        self.assertEqual((NIST_IR_8547_DEPRECATED_AFTER, NIST_IR_8547_DISALLOWED_AFTER), (Y2031, Y2036))

    def test_policy_at_the_disallowed_boundary(self):
        p = AlgorithmPolicy.nist_ir_8547()
        self.assertEqual(p.broken_after, {"ed25519": Y2036})
        for t, trusted in ((Y2036 - 365 * DAY, True), (Y2036 - DAY, True), (Y2036 - 1, True), (Y2036, False),
                           (Y2036 + DAY, False)):
            self.assertEqual(p.trusted_at("ed25519", t), trusted, t)

    def test_2030_and_2035_no_longer_end_trust(self):
        p = AlgorithmPolicy.nist_ir_8547()
        for t in (Y2031 - DAY, Y2031, Y2031 + DAY, 1893456000.0, 2051222400.0, 2051222400.0 + DAY):
            self.assertTrue(p.trusted_at("ed25519", t), t)


@unittest.skipUnless(HAVE_CRYPTOGRAPHY, "needs `cryptography` (the `sign` extra) for Ed25519")
class ThroughVerify(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lte = LongTermEvidence("ab" * 32)
        cls.lte.seal(Signer("ed25519"), 1800000000.0)

    def broken(self, now):
        return any("broken at now" in r for r in self.lte.verify(now=now)["reasons"])

    def test_outer_seal_one_day_before_at_and_after(self):
        for now, broken in ((Y2036 - DAY, False), (Y2036, True), (Y2036 + DAY, True),
                            (2051222400.0 - DAY, False), (2051222400.0, False), (2051222400.0 + DAY, False)):
            self.assertEqual(self.broken(now), broken, now)

    def test_renewal_due(self):
        for now, due in ((Y2036 - DAY, False), (Y2036, True), (Y2036 + DAY, True), (2051222400.0, False)):
            r = self.lte.renewal_due(now)
            self.assertEqual((r["due"], r["breaks_at"]), (due, Y2036), now)

    def test_renewed_too_late(self):
        for t1, late in ((Y2036 - DAY, False), (Y2036, True), (Y2036 + DAY, True), (2051222400.0 + DAY, False)):
            lte = LongTermEvidence("cd" * 32)
            lte.seal(Signer("ed25519"), 1800000000.0)
            lte.seal(Signer("ed25519"), t1)
            reasons = lte.verify(now=t1)["reasons"]
            self.assertEqual(any("renewed too late" in r for r in reasons), late, (t1, reasons))


if __name__ == "__main__":
    unittest.main()
