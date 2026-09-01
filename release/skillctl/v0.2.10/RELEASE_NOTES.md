# skillctl v0.2.10 — security review remediation (SPEC-0266)

Keyless (cosign/OIDC) provenance release. Dual-track install (cosign-preferred,
pinned-ed25519 fallback). Closes the 2026-06-13 adversarial security review.

## P0 (trust spine)
- **F2 + F19** — the self/ER1 sidecar gate now **re-verifies a signed attestation
  against the pinned (off-machine) key**: a repacked `.skb` is denied and
  governance comes from the SIGNED attestation, not the attacker-writable sidecar.
  Trust-roots mandatory when re-anchoring.
- **F1** — post-install bundle revocation: the sweep is the revocation authority
  (quarantines revoked installs + 12h offline cache); a forged revoke is ignored.
- **F12** — gate↔verifier canonicalization fixed point.
- **F25** — credential clients no longer leak `X-API-KEY`/`X-Context-ID` on a
  cross-host redirect.

## P1 (defense-in-depth)
- M7 third TLS path (healthcheck loopback-only), ffmpeg concat-list injection
  guard, F-ENV gate-policy validation, F5 stash hygiene, F4/F9 intrinsic digest binding.

~28 new regression tests; full suite + vet + linux/windows + golangci green.

> **Consumer migration:** reinstall the green skill set so each box carries the
> `.skillctl-attest.json` stash and is re-anchored; ensure `~/.claude/trust-roots.yaml`
> is pinned. Legacy installs WARN + content-bind meanwhile (no breakage).

## Verify
```
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.cosign.bundle \
  --certificate-identity-regexp '^https://github.com/kamir/m3c-tools/\.github/workflows/skillctl-release\.yml@refs/tags/skillctl/v' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
openssl pkeyutl -verify -pubin -inkey skillctl-release.pub -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig
```
