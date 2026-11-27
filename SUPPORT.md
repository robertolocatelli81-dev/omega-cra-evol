# Support

## Where to ask

| You have | Go to |
|---|---|
| a question, an interoperability report, a result from your own verifier | [Discussions](https://github.com/robertolocatelli81-dev/omega-cra-evol/discussions) |
| a defect you can reproduce | an [issue](https://github.com/robertolocatelli81-dev/omega-cra-evol/issues) — what to include is in [CONTRIBUTING.md](CONTRIBUTING.md) |
| a vulnerability | **privately**, as [SECURITY.md](SECURITY.md) says — never in an issue or a discussion |
| a change to propose | [CONTRIBUTING.md](CONTRIBUTING.md) |

Discussions and issues are public and are the project's record: prefer them to e-mail for anything that is not
confidential, so that the answer serves the next person.

## What is supported

- **Releases**: only the **latest release** receives fixes, security fixes included. A fix is published as a new
  release; earlier releases are not patched. Security updates for a release end on the day the next release is
  published. The current release is the first heading of `CHANGELOG.md`.
- **Why so narrow**: the project is in major version 0, with one maintainer; a promise to patch older lines would
  not be kept. This will be revised at 1.0 ([API.md](API.md), "When 1.0").
- **Upgrading is meant to be safe**: within major version 0 the stable API breaks only in a minor release, after a
  deprecation period (API.md), and **evidence already written keeps verifying**: a pack, ledger or attestation made
  by an earlier release is accepted by later ones, because a format changes only under a new identifier.
- **Python**: versions 3.9 to 3.14 are tested in CI on every push and pull request. `requires-python` is `>=3.9`;
  other versions are expected to work and are not claimed until CI runs them.
- **Platforms**: CI runs the whole suite on Linux, macOS and Windows (GitHub-hosted runners).
- **The deprecated import name `cra_evidence`** works and warns until a release on or after 2027-03-31.

## What to expect

- **Security reports**: answered and fixed as soon as possible, with no SLA or fixed deadline (SECURITY.md).
- **Everything else**: best effort by one person, with no promised time. An issue that will not be worked on is
  closed with the reason, not left open.
- **No paid support, commercial licence or pilot is offered at present.**

## What this project does not do

It does not submit anything to the ENISA Single Reporting Platform, does not give legal advice on the Cyber
Resilience Act, and does not certify conformity. The README says what is measured and what is assumed.
