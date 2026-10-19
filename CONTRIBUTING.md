# Contributing

Bug reports, feature requests and pull requests are all welcome. BridgeLab is
defensive security research, and contributions should keep it that way — see
[Responsible use](#responsible-use) below.

## Before you post anything: keep real environments out of it

BridgeLab runs against identity providers and clouds, and it emits telemetry at
every stage of the chain — IdP sign-in logs, cloud audit events, agent traces.
When it runs against a real tenant, that telemetry carries tenant IDs, object
IDs, principal names, tokens, client secrets and access keys. Issues and pull
requests here are **public**.

Never paste an OAuth token, a client secret, an AWS access key, a tenant or
subscription ID, a real principal name, or raw telemetry captured from a real
tenant. Redact it, or describe its shape instead. Everything you share should be
reproducible against the shipped Keycloak + LocalStack sandbox.

Security problems in BridgeLab itself go through private reporting (see
`SECURITY.md` if present), never a public issue. If you have captured live
credentials while testing — for example a real client secret from an Entra run —
rotate or delete them; do not attach them to a report.

## Reporting a bug or asking for a feature

For a bug, include enough to reproduce it:

- the version (`pip show bridgelab`) and your OS and Python version (3.11+),
- how you invoked it — `--mode mock` vs `--mode live`, and the `--technique`,
  `--idp` and `--cloud` values,
- what you expected and what happened instead (with telemetry **redacted**).

The mock-mode chain (`make attack`) needs no Docker and is the easiest thing to
share in a report.

## Pull requests

This repository is published from Cyderes' internal repository: each release
replaces the tree here with a fresh snapshot. So a pull request is **not merged
here directly**.

It is reviewed here, then reapplied internally. If it's accepted, the change
ships in the next snapshot, and the pull request is closed with a link to that
release. By submitting one you agree it is licensed under the Apache License 2.0,
as section 5 of the LICENSE provides for contributions.

To make one easy to accept:

**Keep the dependency surface small.** The runtime depends only on `boto3` and
`httpx`, plus `msal` behind the optional `[entra]` extra and `pytest` behind
`[dev]`. Adding a new runtime dependency needs a reason — raise it in an issue
first.

**Run the tests before you submit.** They run offline, in mock mode, with no
Docker and no cloud:

```bash
make test        # == pytest tests/ -v
```

If your change touches a live path, say in the pull request how you verified it
and against which stack (LocalStack, or an Entra/Azure test tenant you own), and
keep the captured output out of the diff.

**The poison payloads and the crosswalk are the research artifact.** Files under
`infra/poison/` and `output/bridge_crosswalk.json` define what the lab actually
demonstrates — the ATLAS → bridge condition → ATT&CK pivot. A wording change
there changes the claim the lab makes, so call it out explicitly and make sure
the regenerated exports (`make crosswalk`, `make navigator`) match.

**Framework identifiers must be current.** ATT&CK technique IDs must be
**v19**-current (for example `T1685`, not the deprecated `T1562`), and ATLAS IDs
must use the `AML.T` format from the current data release. Verify any ID you add
against attack.mitre.org / the published ATLAS data and cite it.

**Telemetry and labels must stay honest.** A mock run is labeled mock; a dry-run
is not reported as a live capture; a branch that is code-complete but only
mock-verified is not relabeled "(live)". Where a step did not actually perform an
action, the telemetry and the crosswalk's `validated_environments` must say so.
A change that quietly upgrades an unverified or dry-run result to a real one will
be asked to change.

## Responsible use

Contributions must keep BridgeLab defensive and reproducible in a sandbox:

- No real-world or mass targeting, and no code that hardcodes or defaults to a
  live, production, or third-party target.
- Any destructive live path stays behind the explicit confirmation gate
  (`--confirm-destructive`) and defaults to read-only / dry-run.
- Every technique keeps emitting the telemetry that makes the pivot detectable —
  the detection story is the point of the project, not an afterthought.
