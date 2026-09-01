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

## [skillctl/v0.3.0] — 2026-07-10 — enterprise evidence backbone + managed-settings pinning
Full notes: `release/skillctl/v0.3.0/RELEASE_NOTES.md`.
### Added
- **`skillctl pin`** (SPEC-0247 §7.3 P1.3) — pins the trust gate into Claude Code
  **managed settings**, making it un-deletable by non-root users. `generate` /
  `status` / `install`; install **merges** into existing managed policy (never
  clobbers), backs it up, and re-reads the file from disk to verify what landed.
- **`skillctl enforce`** (SPEC-0317 P0) — byte-identical to `verify-hook` for a
  Skill event, plus a transactional **SQLite outbox** (`pkg/skillctl/outbox`,
  hot-path-safe, `spool.jsonl` fallback, write-once rows). The SPEC-0255
  decision-invariance contract is preserved.
- **`skillctl sync --once|--daemon`** (SPEC-0317 P1) — separate-process drain of
  the outbox to the audit-plane ingest contract; marks synced only on a valid
  signed durable-seq; backoff via `delivery_attempts`. HTTPS-only, no Kafka client.
- **`skillctl guard-path`** (SPEC-0317 P2) — side-channel guard over
  Bash/Read/Edit/Write with a single realpath fixed point; audited-allow default.
- **`skillctl session-baseline`** + `pkg/skillctl/statemachine`
  (`online/degraded/offline/locked`) — informational posture.
- **Fleet kill-switch** (FR-0045 D1–D5) — signed revocation HEAD (epoch
  monotonicity, set-root binding), emergency deny-list, opt-in fail-closed
  freshness (exit `22`).
- **`skillctl-demo`** binary + **Kata training mode** (`--mode kata`).
### Security
- **Go 1.26.5** toolchain (`GO-2026-5856`, `crypto/tls` ECH privacy leak);
  `govulncheck` clean.
- **Windows `guard-path` parity** — native `C:\…\SKILL.md` tokens were classified
  "not a path", so the guard never fired on Windows. Fixed; locked by a
  cross-platform test.
### Scope (not claimed)
- Pinning is un-deletable by **non-root only**; root / same-uid is out of scope.
- `guard-path` is **not a seal** (copies outside the skills dir, in-context reads
  and `/slash` are uncovered).
- The state machine is **informational**: the gate does not yet consume
  `require_local_audit` (exit 26) or `locked` (exit 28).
- `sync` is contract-complete against a test double; egress is **default-OFF**.
  Per-batch transparency-log anchoring is not wired (`translog_seq` is NULL).

## [skillctl/v0.2.11] — 2026-06-18 — bundled runbooks + `runbook publish`
Recorded retroactively: this tag shipped without a changelog entry.
### Added
- **Skill-bundled runbooks** (SPEC-0275 P0) — auto-registered on publish.
- **`skillctl runbook publish`** — push an onboarding runbook to the THOH catalog.
- **Opt-in auto-publish** of a runbook on release (SPEC-0272).
- **Author selector** (Eric / Mirko) coupling identity + context + key.
### Fixed
- `publish --attest/--revoke` auto-resolve the digest from the packed `.skb`.
- Release workflow stamps `install.sh`'s `RELEASE_BASE` to the tag.
- Runbook smoke test made optional (skills may ship none); author labels genericised.

## [skillctl/v0.2.10] — 2026-06-13 — security review remediation (SPEC-0266)
Closes the adversarial security review (`CISO-WORK/SECURITY-REVIEW-skillctl-m3c-tools-2026-06-13.md`).
### Security — P0
- **F2 + F19 — self/ER1 sidecar gate re-anchored to the pinned key.** The runtime
  gate now re-verifies a stashed SIGNED attestation (`.skillctl-attest.json`)
  against the pinned (off-machine) trust-root: a repacked self-consistent `.skb`
  is denied (`ErrDigestMismatch`), and governance is read from the SIGNED
  attestation, never the attacker-writable sidecar. Trust-roots MANDATORY when
  re-anchoring; legacy installs WARN + content-bind + flag-for-reinstall.
- **F1 — post-install bundle revocation.** The SessionStart sweep is the
  revocation authority (fail-open fetch → quarantines revoked installs + writes a
  12h cache); the offline gate denies revoked skills from that cache. A forged
  (unsigned) revoke is ignored.
- **F12 — gate↔verifier canonicalization fixed point** (`CanonicalSkillName`):
  a name is rejected or used verbatim, so a clean sibling can't be verified while
  a malicious dir loads.
- **F25 — credential-redirect leak**: ER1/session/plaud/pocket clients no longer
  re-emit `X-API-KEY`/`X-Context-ID` on a cross-host redirect (`NoCredentialRedirect`).
### Security — P1
- **M7 (third path)**: the `pkg/config` TestConnection healthcheck honours
  `ER1_VERIFY_SSL=false` only for loopback; remote hosts force verification on.
- **ffmpeg concat-list injection**: Pocket merge rejects `\n`/`\r`/NUL in a
  recording path before building the `-safe 0` concat list.
- **F-ENV**: `unmanaged_skills` / `SKILLCTL_GATE_UNMANAGED` validated against
  {deny,warn,allow}; unknown → fail-closed deny.
- **F5**: content-binding flags planted nested stash-named files; `findStashedSkb`
  refuses >1 top-level `.skb`.
- **F4/F9**: bundle signatures verified over the recomputed digest (intrinsic binding).
### Notes
~28 new regression tests; full skillctl suite + `go vet` + linux/windows + golangci
green on every commit. The `m3c-tools` product-binary fixes (device-hub, F25 device
client, ffmpeg) also ride the next `v*` product cut. Operational follow-up: reinstall
the green skill set on consumer boxes so they carry the attestation stash (SPEC-0266).

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
