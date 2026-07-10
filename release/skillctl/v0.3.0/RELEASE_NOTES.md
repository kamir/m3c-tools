# skillctl v0.3.0 — enterprise evidence backbone + managed-settings pinning

Keyless (cosign/OIDC) provenance release. Dual-track install (cosign-preferred,
pinned-ed25519 fallback) — unchanged from v0.2.8.

The largest cut since the trust gate landed: the runtime gate becomes
**un-deletable by non-root users**, and enforcement decisions gain a durable,
local-first evidence store with an eventual central sync path.

## Added

- **`skillctl pin`** (SPEC-0247 §7.3 P1.3) — pins the trust gate into Claude
  Code **managed settings**, the one tier a non-privileged user cannot edit.
  `generate` emits the canonical hook wiring; `status` reports
  `absent/tampered/partial/pinned/pinned-strict`; `install` **merges** into any
  existing managed policy (never clobbers), backs it up, and — only as root with
  `--confirm` — writes it, then re-reads the file from disk and verifies what
  actually landed. `--strict` adds `allowManagedHooksOnly` and warns loudly that
  it disables every other user hook.
- **`skillctl enforce`** (SPEC-0317 P0) — byte-identical to `verify-hook` for a
  Skill event, and additionally mirrors the device-signed `InvocationRecord`
  into a new transactional **SQLite outbox** (`pkg/skillctl/outbox`). Hot-path
  safe (single pinned connection, `busy_timeout=250ms`, `spool.jsonl` fallback);
  write-once rows enforced by SQL triggers. The SPEC-0255 decision-invariance
  contract holds: an outbox-write failure can never change a gate decision.
- **`skillctl sync --once|--daemon`** (SPEC-0317 P1) — a **separate process**,
  never on the hook path, that drains the outbox over HTTPS to the audit-plane
  ingest contract. Marks a row synced **only** on a valid signed durable-seq ack;
  backoff-gated retries via `delivery_attempts`; replay of an acked `event_id` is
  a no-op. No Kafka in the client.
- **`skillctl guard-path`** (SPEC-0317 P2) — a side-channel guard for
  Bash/Read/Edit/Write against skill directories, with a single
  realpath-canonicalisation fixed point. **Audited-allow by default**, opt-in
  deny.
- **`skillctl session-baseline`** — prints the offline posture
  (`online/degraded/offline/locked`) from the new `pkg/skillctl/statemachine`.
- **Fleet kill-switch** (FR-0045 D1–D5) — signed revocation HEAD with epoch
  monotonicity + set-root binding, an emergency deny-list consulted first and
  unconditionally, and opt-in fail-closed revocation freshness (exit `22`).
- **`skillctl-demo`** — a self-contained offline CISO skill-trust demo binary,
  plus a hands-on **Kata training mode** (`--mode kata`): five katas, each
  driving a real skillctl exit code.

## Security & CI

- **Go 1.26.5** toolchain (`GO-2026-5856`, `crypto/tls` ECH privacy leak). This
  release is built with the patched stdlib; `govulncheck` is clean.
- **Windows parity fix** — `guard-path` classified native `C:\…\SKILL.md` tokens
  as "not a path", so the guard never fired on Windows. Fixed and locked by a
  cross-platform test.
- Command packages now run under `-race` in CI.

## What this release does NOT claim (honest scope)

Read this before quoting the feature list:

- **Pinning is un-deletable by *non-root* users only.** Root, or anyone able to
  write the managed-settings directory, can still remove it. A same-uid attacker
  is explicitly out of scope (SPEC-0247 §3.2/§7.3).
- **`guard-path` is not a seal.** It raises cost and creates an audit signal.
  Copies made outside the skills dir, content already read into context, and the
  `/slash` prompt-expansion path are **not** covered.
- **The offline state machine is informational, not yet enforcing.**
  `session-baseline` prints the posture, but the runtime gate does not yet consume
  `require_local_audit` (exit 26) or `locked` (exit 28).
- **`sync` is contract-complete against a test double.** The durable audit
  backend is a separate track; egress ships **default-OFF** pending an egress
  contract. Local evidence is fully functional without it.
- **Per-batch transparency-log anchoring is not wired** (`translog_seq` is NULL
  in production). Tamper-evidence is scoped to the signed durable-seq path once
  synced — not to local log monotonicity.

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
