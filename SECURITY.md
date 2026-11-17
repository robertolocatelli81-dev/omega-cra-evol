# Security policy

Report a vulnerability in this repository privately — through GitHub's "Report a vulnerability" (Security tab →
Advisories), or to the author (roberto.locatelli.81@gmail.com) — with the
commit hash and a reproducer. This is non-commercial open source maintained by one person: reports are answered
and fixed as soon as possible, with no SLA or fixed deadline; fixed versions are tagged and listed in CHANGELOG.md
with the reporter's credit if wanted. This project keeps its own SBOM and vulnerability-handling evidence with itself — the same
discipline it asks of its users: each release carries its own SBOM, ledger and KMS-signed evidence pack among its
release assets; `examples/self_evidence/` is the worked example of the same, made by version 0.4.0 (see
`examples/README.md`).

Scope: the code in this repository. Out of scope: the ENISA Single Reporting Platform, OSV.dev, CISA KEV and the
EUVD, which are third-party services this tool only reads.
