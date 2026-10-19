# Security policy

## Reporting a vulnerability

Report security problems privately, through GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability).
Please don't open a public issue for one.

A useful report says which version you have (`pip show bridgelab`), how you
invoked BridgeLab (`--mode`, `--technique`, `--idp`, `--cloud`), what you did,
and what happened. Leave out real OAuth tokens, client secrets, access keys,
tenant or subscription IDs, and raw telemetry; a redacted example is enough. If
you captured live credentials while testing, rotate or delete them rather than
attaching them to a report.

## What a vulnerability means here — and what it doesn't

BridgeLab is defensive security research whose **purpose** is to demonstrate the
ATLAS → ATT&CK agent-identity pivot. The attack techniques it runs, the poison
payloads in `infra/poison/`, and the deliberately-escalatable roles the sandbox
seeds are the research artifact, not bugs. A report that BridgeLab "performs an
attack" is describing the feature.

A vulnerability is BridgeLab's own code doing something **unintended or unsafe
beyond its sandbox contract**. These matter most:

- **Escaping the sandbox contract.** Anything that lets a live destructive path
  run without the explicit `--confirm-destructive` gate, or that makes a run
  default to — or silently point at — a real/production target instead of the
  shipped Keycloak + LocalStack sandbox or the test tenant the user named.
- **Credential handling.** Any way for a token, client secret, or access key to
  leave the local environment, reach a host other than the configured IdP or
  cloud endpoint, or appear in committed output, logs, or generated artifacts.
- **Telemetry and output integrity.** Captured telemetry, seeded secrets, or
  live credentials surviving into `output/` or anything a user would commit; or
  a dry-run/mock result being emitted as though it were a real live capture.
- **Supply chain.** Anything that could make an install or run fetch, unpack, or
  execute code that is not part of this repository or its declared dependencies.

## Out of scope

- The attack techniques, poison documents, and intentionally weak/escalatable
  IAM policies the lab ships — these are deliberate.
- MITRE ATT&CK / ATLAS content, and upstream components invoked or depended on
  (LocalStack, Keycloak, boto3, httpx, msal, Docker images). Report those to
  their respective projects.
- The behavior of any real Entra ID / Azure or AWS tenant you point the lab at;
  securing a tenant you own is your responsibility, and issues with those
  platforms go to the platform vendor, not here.

This is unsupported research code published as-is. There is no support channel,
SLA, or guarantee of a response or fix beyond the private vulnerability-reporting
path above.

## Supported versions

This project is pre-1.0; only the latest published snapshot is supported. Fixes
ship as a new snapshot rather than as a backport.
