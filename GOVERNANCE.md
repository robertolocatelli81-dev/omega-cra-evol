# Governance

## Who decides

omega-cra-evol has **one maintainer**, Roberto Locatelli, who holds the copyright, decides what is merged and released,
and answers for it. Changes written with the help of his AI agent (Noûs) are reviewed by him and signed as such.

| Access | Who |
|---|---|
| Merge to `master`, tags, releases, repository settings | the maintainer |
| Publishing to PyPI (environment `pypi`, approved by a person for each release) and to GHCR | the maintainer |
| Signing keys of releases and evidence packs | the maintainer |

## How decisions are made

- The formats (ledger, evidence pack, `art14-filing`, receipts) are specified in `spec/` before they are coded; a rule
  that changes takes a new version or identifier, so that evidence already written keeps verifying.
- Defects reported publicly are answered in the issue; vulnerabilities as [SECURITY.md](SECURITY.md) says.
- What the project relies on and what it promises are in [API.md](API.md) and [SUPPORT.md](SUPPORT.md).

## What is not met today

- **No second reviewer.** Every change is reviewed by its author only; reviews named in the CHANGELOG are run by the
  same author, not by a third party.
- **No external code contributions** ([CONTRIBUTING.md](CONTRIBUTING.md)).

## Continuity

The code, the specifications and the release history are public under AGPL-3.0-or-later: anyone may keep using,
studying, changing and redistributing them under that licence, also if the maintainer stops. Releases stay on GitHub,
PyPI and Zenodo (concept DOI in `CITATION.cff`).
