# skillctl v0.2.9 — lifecycle validation harness + constrained-low closure

Keyless (cosign/OIDC) provenance release. Dual-track install (cosign-preferred,
pinned-ed25519 fallback) — unchanged from v0.2.8.

## Added
- **Lifecycle tamper-detection harness** (SPEC-0265): a hermetic Go E2E
  (`TestLifecycleTamper_E2E`) and an operator shell simulation
  (`tools/lifecycle-tamper-sim/run.sh`, `--mode local|ssh`) that drive the **real**
  binary through bundle → install → tamper → **block (exit 2)** → **quarantine** →
  **gate-stats alert**. The shell harness runs the tamper over SSH on a remote
  Linux box (the production-shaped target) and emits a compliance evidence pack.
  Backed by `CISO-WORK/TEST-CONCEPT-skillctl-lifecycle-tamper-detection.md`.
- **SBOM release asset** (CycloneDX) — emitted alongside the signed artifacts
  (WARN-only; a syft hiccup never blocks a cut). Closes the optional SPEC-0253
  follow-up.

## Security (constrained lows, 2026-06-10 audit)
- **M10** — login-callback Device Hub reflected XSS closed: `context_id`/`baseURL`
  HTML-escaped + strict CSP (`default-src 'none'; style-src 'unsafe-inline'`) +
  `nosniff`/`no-referrer`. Regression test.
- **L7** — Plaud S3 allowlist hardened: `https`-only, S3 bucket-style hosts only
  (dropped broad `*.amazonaws.com`/`*.cloudfront.net` wildcards; CloudFront
  pinned), read ceilings 50 MB → 16 MB. Regression test.
- **L5** (device token off the GET query string) deferred — cross-system ER1+client
  contract change; tracked.

## Verification
```
# cosign (keyless) — when cosign is present:
cosign verify-blob SHA256SUMS \
  --bundle SHA256SUMS.cosign.bundle \
  --certificate-identity-regexp '^https://github.com/kamir/m3c-tools/\.github/workflows/skillctl-release\.yml@refs/tags/skillctl/v' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'

# ed25519 fallback (pinned fingerprint):
openssl pkeyutl -verify -pubin -inkey skillctl-release.pub \
  -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig
```

The skillctl binary itself is functionally unchanged from v0.2.8 (this cut adds
the SBOM provenance asset + tags the validated tree state); the M10/L7 fixes live
in the `m3c-tools` product binary and ride the next `v*` product cut.
