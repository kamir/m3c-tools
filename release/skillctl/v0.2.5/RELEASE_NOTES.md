# skillctl v0.2.5 — P1 hardening

Trust-and-governance CLI for AI-agent skills. Single static Go binary — no Node.

> Builds on the **v0.2.4 security release** (7 P0 fixes). This release lands the
> SPEC-0251 **P1 hardening** batch. Recommended upgrade.

## Install (verifies signature + checksum)

```sh
curl -fsSL https://github.com/kamir/m3c-tools/releases/download/skillctl/v0.2.5/install.sh \
  | RELEASE_BASE=https://github.com/kamir/m3c-tools/releases/download/skillctl/v0.2.5 bash
```

## P1 hardening (SPEC-0251)
- **Load-time gate is panic-safe by design** — a panic anywhere in `verify-hook`
  now yields a fail-closed DENY (exit 2), never a crash the harness might read as allow.
- **Strict, fail-closed policy & trust-roots** — `gate-policy.yaml` and the self
  trust-roots parse strictly (unknown/typo'd fields no longer silently allow-all);
  `governance_minimum: red` is rejected and the floor is case-normalised so it can't
  collapse.
- **Install-token fails closed** on RNG failure (no world-known fallback key on the
  destructive-overwrite guard).
- **Verdict cache** uses a unique temp file per write (no concurrent-rename corruption).
- **TLS:** `ER1_VERIFY_SSL=false` is honoured **only for loopback** — verification is
  forced on for any remote host (closes a stage/unknown-target downgrade).
- **Windows URL/file open** uses `rundll32 url.dll,FileProtocolHandler` (no `cmd /c
  start` metacharacter surface), everywhere.
- **Plaud token** via env / `--token-file` (bare-argv form deprecated + warned);
  DocID validated; `findSetupScript` anchored to the binary path.
- **CI** now runs the skillctl security tests under `-race`.

Carries forward SPEC-0246 `publish --share-room` / `room share|unshare`;
`skillctl version` prints the stamped tag.

## Provenance
Binaries are checksummed (`SHA256SUMS`) and the manifest is ed25519-signed
(`SHA256SUMS.sig`) by the skillctl **release key** (separate from skill-author
keys). Verify against the pinned public key:

- `skillctl-release.pub` (also at `INFRA/skillctl-release.pub` in the repo)
- K-release fingerprint: `sha256:5f8f39cb0454dcd8ac04c6729af2fa4b71a13a5e125e56924701d9e38187a9c2`

```sh
openssl pkeyutl -verify -pubin -inkey skillctl-release.pub -rawin \
  -in SHA256SUMS -sigfile SHA256SUMS.sig
```
