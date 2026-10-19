# Changelog

All notable changes to BridgeLab are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
No public release has been tagged yet; everything below `0.1.0` is work toward
the first public cut.

## [Unreleased]

### Added
- `disable-cloud-log` technique (**T1685.002**, ATT&CK v19 — the former
  T1562.* now merged into T1685), with both a LocalStack branch and an Azure
  branch, live-verified end to end on both stacks.
- Abort-before-delete pre-flight for the Azure log-disable path, so a failed
  precondition stops the run before anything is removed.
- `create-account` technique (**T1136.003**) for Azure and LocalStack;
  live-verified on Entra/Azure, LocalStack branch code-complete and
  mock-verified.
- Apache-2.0 `LICENSE`, a "Responsible use" note in the README, and this
  `NOTICE` / `CONTRIBUTING.md` / `CHANGELOG.md` documentation set, preparing the
  repository for public release.

### Changed
- `LICENSE` copyright holder set to **Cyderes**.
- Regenerated `output/bridge_crosswalk.json` and
  `output/bridge_navigator_layer.json` to reflect newly validated environments.
- Retry Azure AD Graph app deletion to survive directory replication lag
  (T1136.003).

## [0.1.0] — 2026-06-24

Initial BridgeLab: a reproducible lab demonstrating the ATLAS → ATT&CK v19
agent-identity pivot, plus the takeaway artifacts.

### Added
- **Project scaffolding** — `pyproject.toml`, `Makefile`, and the
  `bridgelab-crosswalk` / `bridgelab-navigator` / `bridgelab-attack` CLIs.
- **Bridge Crosswalk** — 10 mapped ATLAS → ATT&CK v19 pivots with bridge
  conditions and detection opportunities, exported as JSON and CSV.
- **ATT&CK Navigator layer** generator (Navigator v4.5) built from the crosswalk.
- **Attack-chain orchestrator** — ATLAS → bridge → ATT&CK → impact, emitting
  telemetry at every stage; agent with tools, auth, and the poison document.
- **Sandbox lab** — Docker Compose standing up a Keycloak IdP and a LocalStack
  AWS sandbox, with generated output artifacts from a live run.

### Added — techniques and backends (post-scaffold, toward first release)
- Split the live backend into independent `identity_provider` / `cloud_target`
  axes, exposing `--idp`, `--cloud`, and `--confirm-destructive`.
- **Entra ID / Azure** support — `EntraAgentAuth` (MSAL `client_credentials`
  against a real Entra tenant) and a real `AzureIAMTool`, wiring the live
  Entra → Azure escalation path alongside the Keycloak + LocalStack path.
- `additional-credentials` (default) — **T1098.001**, agent adds a persistent
  credential with its own token.
- `additional-roles` — **T1098.003**, agent self-escalates by attaching an
  admin policy to itself (LocalStack); read-only on Azure by design.
- `out-of-scope-access` — **T1550.001**, lateral movement / scope creep with a
  token that was always valid; validated read-only against Entra/Azure.
- `data-collection` — **T1530**, cloud-storage collection on LocalStack and
  Entra/Azure, live-verified.
- Per-technique Mermaid sequence diagrams in the README, with `alt`/`else`
  branches where LocalStack and Azure genuinely diverge, replacing the earlier
  ASCII diagrams.
- `docs/entra-setup.md` setup guide and `.env.example`.

### Fixed
- Load `.env` for the `bridgelab-attack` CLI.
- Point `AzureIAMTool` at `/applications` rather than `/servicePrincipals`.
- Correct the `KEYCLOAK_URL` default port in `.env.example` to `8180`.
- Drop the unused `--crosswalk` argument.

[Unreleased]: https://keepachangelog.com/en/1.1.0/
