# skillctl v0.2.6 — P2 trust-chain convergence

Trust-and-governance CLI for AI-agent skills. Single static Go binary — no Node.

> Builds on **v0.2.4** (7 P0 security fixes) and **v0.2.5** (P1 hardening). This
> release lands the **SPEC-0252 trust-chain convergence** — a structural refactor
> that removes the copy-paste drift behind the audit's "weak twin" findings.
> **No new feature surface; no behaviour change for honest bundles.** Recommended upgrade.

## Install (verifies signature + checksum)

```sh
curl -fsSL https://github.com/kamir/m3c-tools/releases/download/skillctl/v0.2.6/install.sh \
  | RELEASE_BASE=https://github.com/kamir/m3c-tools/releases/download/skillctl/v0.2.6 bash
```

## What changed (SPEC-0252)

The most security-sensitive code — *decompress an attacker-influenced gzip+tar
and turn its entries into files on disk* — used to be implemented **three times**
(HTTP install, self/ER1 install, and the hot per-invocation gate comparator),
each with its own path-sanitiser, wrapper-strip, bomb caps, and file-mode logic.
Every hardening fix had to be applied two or three times, and they had drifted.
v0.2.6 collapses them onto **one hardened core** (`pkg/skillbundle.Unpack` /
`ExtractTo` / `SafeJoin`):

- **One gzip+tar reader.** Single decompression pass; per-entry `io.LimitReader`
  against a running byte ceiling (gzip-bomb) + a file-count cap (tar-bomb);
  one path-escape proof; symlink/hardlink/device refusal; `O_EXCL` fail-closed
  writes; one `scripts/*`→0755-else-0644 mode policy.
- **One wrapper-strip rule** — the installer and the integrity check can no
  longer disagree on which files belong to a signed bundle.
- **One canonical extraction cap** definition (install/registry now alias it).
- **Stricter sanitiser** — absolute / `..`-escaping / Windows-volume / backslash /
  NUL names are now **rejected** (the old self/ER1 path silently *rewrote*
  traversal); the gate comparator now fails closed on a `.skb` carrying a
  symlink (previously skipped).
- **One governance-level guard** (`pkg/skillctl/govlevel`) shared by both
  trust-root loaders — permanently closes the **SEC-L1** case-collapse class
  (a mixed-case `governance_minimum` can never silently disable the gate).

**Adversarially verified:** an independent review tried to prove the converged
path weaker than any of the three originals across 9 input classes and could
not — it found only tightenings. Build + `go vet ./...` + the full skillctl
security suite under `-race` are green.

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
