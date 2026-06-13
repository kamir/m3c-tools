# Changelog

All notable changes to **skillctl** (the trust-and-governance CLI) are recorded
here. Format follows [Keep a Changelog](https://keepachangelog.com/); the runtime
version is ldflags-stamped (`skillctl version`). Release tags: `skillctl/vX.Y.Z`
(the `m3c-tools` product line uses separate `vX.Y.Z` tags).

## [Unreleased]
### Pending
- Multi-platform parity (SPEC-0251 §5 / project ST-002): promote the remaining
  darwin-coupled `m3c-tools` subcommands — `import-audio` (decouple the
  `reverseTracker` package var init'd in darwin `main()` + the `*menubar.App` /
  `menubarWhisper*` web) and the `pocket` cloud-sync cluster — off the darwin-only
  `main.go`, plus the `cmdTranscript`/`cmdCheckER1` dedup. Deliberately deferred:
  a verbatim move ships half-extracted shared state, so it needs a dedicated
  refactor pass, not a release-eve edit.

## [skillctl/v0.2.9] — 2026-06-13 — lifecycle validation harness + constrained-low closure
### Added
- **Lifecycle tamper-detection harness** (SPEC-0265, derived from
  `CISO-WORK/TEST-CONCEPT-skillctl-lifecycle-tamper-detection.md`): a hermetic Go
  E2E (`TestLifecycleTamper_E2E`) and an operator shell simulation
  (`tools/lifecycle-tamper-sim/run.sh`, `--mode local|ssh`) that drive the **real**
  binary through bundle → install → tamper → **block (exit 2)** → **quarantine** →
  **gate-stats alert**. The shell harness runs the tamper over SSH on a remote
  Linux box (the production-shaped target) and emits a compliance evidence pack.
- **SBOM release asset** (SPEC-0253 follow-up): `skillctl-release.yml` emits a
  CycloneDX SBOM of the Go build inputs alongside the signed artifacts (WARN-only;
  a syft failure never blocks a cut).
### Security
- **M10 — reflected XSS on the login-callback Device Hub page** closed: the raw
  `context_id` (and `baseURL`) are now `html.EscapeString`-escaped, and the
  throwaway page is served under a strict CSP (`default-src 'none'; style-src
  'unsafe-inline'`) + `X-Content-Type-Options`/`Referrer-Policy`. Regression test
  added.
- **L7 — Plaud S3 allowlist hardening**: require `https` (no cleartext downgrade);
  drop the over-broad `*.amazonaws.com`/`*.cloudfront.net` wildcards in favour of
  S3 bucket-style hosts only, CloudFront pinned to the explicit distribution; S3
  content + API read ceilings lowered 50 MB → 16 MB. Regression test added.
### Deferred
- **L5 — device token transits the login callback as a GET query param**: the fix
  (POST/fragment/one-time code) is a cross-system contract change requiring the ER1
  server's redirect to change in lockstep, so it cannot land unilaterally without
  breaking login. Tracked; blast radius is constrained (browser history on a
  nonce'd loopback page).

## [skillctl/v0.2.8] — 2026-06-11 — keyless provenance (cosign/OIDC)
### Added
- **Release-signing in CI** (SPEC-0253) — **first keyless cut**:
  `.github/workflows/skillctl-release.yml` builds the 5-arch set on go1.26.4 and
  keyless-signs `SHA256SUMS` with **Sigstore cosign + GitHub OIDC** (no private key
  in the repo or workflow secrets), self-verifies against the workflow identity,
  and emits a **SLSA `attest-build-provenance`**. Creates a draft; the operator
  attaches the ed25519 `SHA256SUMS.sig` (signed over the CI's exact bytes) and
  promotes.
- **Dual-track `install.sh`**: cosign-preferred (verifies against the expected
  OIDC identity when cosign is present), pinned-ed25519 fallback otherwise;
  `SKILLCTL_REQUIRE_COSIGN=1` to force keyless. A present-but-invalid cosign bundle
  hard-fails (fail-closed, SEC-M2). Verified live end-to-end on both tracks.
- Sample scheduling units for the revocation sweep (`tools/scheduling/`: launchd,
  systemd timer, cron, Windows Task Scheduler).

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
