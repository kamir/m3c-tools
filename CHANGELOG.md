# Changelog

All notable changes to **skillctl** (the trust-and-governance CLI) are recorded
here. Format follows [Keep a Changelog](https://keepachangelog.com/); the runtime
version is ldflags-stamped (`skillctl version`). Release tags: `skillctl/vX.Y.Z`
(the `m3c-tools` product line uses separate `vX.Y.Z` tags).

## [Unreleased]
### Added
- **Release-signing in CI** (SPEC-0253, staged): `.github/workflows/skillctl-release.yml`
  keyless-signs `SHA256SUMS` with Sigstore cosign + GitHub OIDC and emits SLSA
  build provenance; `install.sh` is dual-track (cosign-preferred, pinned-ed25519
  fallback). Activates on the next `skillctl/v*` cut.
- Sample scheduling units for the revocation sweep (`tools/scheduling/`: launchd,
  systemd timer, cron, Windows Task Scheduler).
### Pending
- Multi-platform parity (SPEC-0251 §5): promote the portable `m3c-tools`
  subcommands off the darwin-only `main.go` so linux/windows expose them.

## [skillctl/v0.2.7] — 2026-06-11 — hygiene, hardening & observability
### Security
- **Toolchain → go1.26.4**: clears **14 reachable Go-stdlib CVEs** the older
  toolchain shipped into binaries (govulncheck 14 → 0).
### Added
- `govulncheck` + `gitleaks` CI gates; `dependabot.yml`.
- `skillctl gate-stats` + append-only `~/.claude/skillctl/gate-audit.jsonl`
  (SPEC-0255) — advisory, decision-invariant under logging failure.
- Exit-code single-source guard tests (SPEC-0251 §5) pinning the 10–19 ladder.
### Removed
- Four dead `//nolint:unused` symbols — zero suppressions; `unused` re-armed.

## [skillctl/v0.2.6] — 2026-06-11 — trust-chain convergence (SPEC-0252)
### Changed
- Collapsed three drifted gzip+tar extractors → one hardened `pkg/skillbundle.Unpack`;
  two wrapper-strip helpers → one; duplicated caps → one canonical definition;
  two governance-floor sets → one `pkg/skillctl/govlevel` (closes the SEC-L1
  case-collapse class). Adversarially verified equivalent-or-stricter.

## [skillctl/v0.2.5] — 2026-06-10 — P1 hardening (SPEC-0251)
### Security
- Panic-safe fail-closed load gate; strict fail-closed policy & trust-roots;
  install-token fails closed on RNG failure; verdict-cache atomic write;
  `ER1_VERIFY_SSL=false` honoured only for loopback; Windows URL/open via
  `rundll32`; Plaud token via env/`--token-file`. CI runs the skillctl tests
  under `-race`.

## [skillctl/v0.2.4] — 2026-06-10 — P0 security must-fixes (SPEC-0251)
### Security
- Attest/revoke envelope signatures verified (closes the one HIGH — forged
  governance verdict); weak-twin extractor bomb-capped + content-binding
  unconditional; release installer pins the K-release fingerprint; unsanitized
  bundle-name fixed; sidecar verify fails closed.

## [skillctl/v0.2.3] — 2026-06 — prerelease (superseded)
