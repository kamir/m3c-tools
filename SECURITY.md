# Security policy

`skillctl` is a trust tool, so we hold its own supply chain to the standard it asks of others.
This document says how to report a vulnerability and how to verify what you install.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.** Report it privately through
GitHub's **[Security Advisories](https://github.com/kamir/m3c-tools/security/advisories/new)**
("Report a vulnerability" on the repository's *Security* tab). Include:

- affected component (`m3c-tools`, `skillctl`, an install script, a workflow) and version/commit;
- a minimal reproduction and the impact you observed;
- any suggested remediation.

We aim to acknowledge a report within a few working days and to coordinate a fix and disclosure
timeline with you. Please give us a reasonable window to remediate before any public disclosure.

## Supported versions

Security fixes target the **latest** release of each line — `vX.Y.Z` (product) and
`skillctl/vX.Y.Z` (the signed trust CLI). Older tags are not maintained; upgrade to the latest
release.

## Supply-chain guarantees

Every release is built and signed in GitHub Actions — there is **no long-lived signing key** in
the repository:

- **Keyless cosign signatures** over the release checksums, via GitHub OIDC. The signing job
  verifies its own signature in-job, so a broken signature fails the release rather than shipping
  unsigned.
- **SLSA build provenance** (`multiple.intoto.jsonl`), gated by `slsa-verifier`; the signed
  `skillctl/v*` line targets **SLSA Level 3**.
- **ed25519 fallback signature** on the skillctl `SHA256SUMS`, verified against the pinned
  `skillctl-release.pub`, so hosts without cosign still get an integrity guarantee.
- **CycloneDX SBOM** shipped with the skillctl release.
- **Pinned bootstrap.** The install one-liners pin an immutable commit and each script's SHA-256,
  not the mutable `master` branch.

## Verifying a release

**cosign (product line):**

```bash
cosign verify-blob checksums.txt \
  --bundle checksums.txt.cosign.bundle \
  --certificate-identity-regexp '^https://github.com/kamir/m3c-tools/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

**SLSA provenance:**

```bash
slsa-verifier verify-artifact <asset> \
  --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/kamir/m3c-tools
```

**Skills you install with `skillctl`** are verified **offline** — the ed25519 trust chain is
checked with no server and no hosted CA in the verification path, and revocation is signed,
offline and fail-closed:

```bash
skillctl verify-sig my-skill.skb --pubkey trusted.pub   # no network
```

See [docs/releasing.md](docs/releasing.md) for the full signing and provenance flow.
