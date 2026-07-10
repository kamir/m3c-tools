---
layout: default
title: Manual — skillctl
---

# Manual: skillctl

`skillctl` is the trust-and-governance CLI for agent skills. Every skill gets a verifiable
identity and a full lifecycle — **author → pack → sign → admit → attest → verify / install →
use → audit → revoke** — so nothing an agent runs is unauthorized or unprovable. The
trust-chain check is **offline-verifiable: no external authority sits in the verification
path.** A hosted registry, ledger, or transparency log is *complementary*, not required to
prove a bundle authentic.

> **New here?** The [Quickstart: skillctl](quickstart-skillctl.md) walks the happy path in
> about five minutes. This manual is the exhaustive reference — every command, every flag,
> every exit code, derived from `skillctl help` and each command's `--help`.

`skillctl` ships in the same repository as `m3c-tools` and reuses its ER1 device login
(`skillctl login`) for any command that talks to a registry.

---

## Installation

`skillctl` is a single, dependency-light CLI binary. It runs identically on macOS, Linux and
Windows. Grab the platform binary from a
[release](https://github.com/kamir/m3c-tools/releases/latest), or build from source:

```bash
go build -o build/skillctl ./cmd/skillctl
```

See the [Quickstart](quickstart-skillctl.md#1-install) for one-line install commands per
platform.

```bash
skillctl version          # print the build version
skillctl help             # the full command map, grouped by capability
```

`skillctl help` groups commands by the SPEC that introduced them: **S1** signing, **device
login**, **S7** trust roots, **S8** install/verify, **SPEC-0247** the Claude Code trust gate,
**SPEC-0277** AgentID, **SPEC-0195** the awareness bridge, **SPEC-0214** PLM project context,
**SPEC-0225** the personal registry, **SPEC-0213** session-state, and **SPEC-0278** the L1
transparency log. Run any command with `--help` for its flags.

---

## Concepts

| Term | Meaning |
|------|---------|
| **`.skb` bundle** | A sealed skill bundle: a `SKILL.md`-bearing skill directory packed with a signed manifest (`bundle.json`). Its SHA-256 digest is the bundle's stable identity. |
| **Author signature (detached)** | An ed25519 signature over the bundle's 32-byte digest, written *next to* the bundle as `<bundle>.<digest_hex>.author.sig`. Anyone with the author's public key can verify it offline. |
| **Trust roots** | `~/.claude/skill-trust-roots.yaml`: the registry public keys *you* have pinned. The verifier trusts only these. Multiple keys per registry support rotation overlap windows. |
| **Registry** | Where admitted bundles and their governance events live. Can be a `self` ER1 registry (personal) or an HTTP registry. The registry is a *distribution + audit* surface — it is **not** in the cryptographic verification path. |
| **Admit / attest** | *Admit* publishes a bundle to a registry. *Attest* posts a signed governance verdict on an admitted digest. Attestations — not author intent — are what bind governance. |
| **Governance level (green/yellow/red)** | The verdict carried by an attestation. Install/verify enforce a configurable minimum (default green). Author *intent* is advisory; the verifier ignores it. |
| **Revocation + freshness** | A signed, offline-verifiable revocation list. Freshness contracts (SPEC-0279) fail **closed**: a stale, rolled-back, or forged revocation list is rejected rather than silently trusted. A signed checkpoint can reset the staleness clock; a signed emergency deny-list denies a named digest immediately. |
| **AgentID** | An owner-signed *mandate* stating that a specific agent instance may use these skills for these intents. It verifies **offline** against pinned owner/approver keys — no authority in the path. |
| **Transparency log (translog)** | A local RFC-6962 Merkle log (SPEC-0278, "L1"). It makes equivocation and withholding **detectable**, and emits offline inclusion receipts. It does not gate installs; L2 (BFT ledger) and L3 (public anchoring) are deferred. |
| **The fail-closed gate** | `verify-hook` is a Claude Code `PreToolUse(Skill)` hook. It verifies the trust chain before any skill runs and emits allow/deny. If it cannot read or verify, it **denies** — fail-closed. |

---

## Exit codes

The verifier (`install`, `verify`, and the gate) returns **numbered** exit codes so
automation can branch precisely. This is the authoritative table, sourced from
`skillctl trust --help` / `install --help` / `verify --help`.

| Code | Meaning |
|-----:|---------|
| `0` | ok |
| `1` | generic error (including network / non-2xx) |
| `2` | usage / flag error |
| `10` | digest mismatch |
| `11` | author signature invalid |
| `12` | registry not in trust roots |
| `13` | governance below minimum |
| `14` | `depends_on` unsatisfied |
| `15` | blob missing |
| `16` | tenant blocked (CISO console verdict) |
| `17` | revoked / emergency deny (from a signed revocation or emergency list) |

Additional codes surface in specific commands:

| Code | Command(s) | Meaning |
|-----:|------------|---------|
| `3` | `audit` | at least one skill is `BROKEN`. |
| `4` | `import-public` | pin required (input validation). |
| `5` | `import-public` | scanner refuse (scanner / policy hit). |
| `6` | `import-public` | bodyscan refuse. |
| `18` | `intent declare`, `import-public` | intent inconsistent with `data_dependencies` (SPEC-0196 §3.3); also intent-capped on import. |
| `19` | `awareness reset`, `import-public` | identity mismatch — `client_identity` ≠ `admitted_by_identity`; also source-blocked on import. |
| `20` | `agentid verify` | self-attested / approver-floor not met (reviewer_id == author_id; SPEC-0246 §5.2). |
| `21` | `agentid verify` | AgentID mandate expired. |
| `22` | `agentid verify`, `verify --bundle`, `verify-hook` | revocation snapshot stale — freshness fail-closed (SPEC-0279 R3 / FR-0045 D4). |
| `23` | `translog verify`, `verify` | transparency-log inclusion missing / receipt not included (SPEC-0278 L1). |
| `24` | `translog witness` | split-view (equivocation) detected. |
| `25` | `translog consistency` | consistency / append-only rewrite violation detected. |
| `32` | *(ROADMAP — not implemented)* | runtime capability-envelope (egress) violation. Appears **only** in the demo's ROADMAP scenario; **no** current `skillctl` subcommand emits it (the Go-native OS-level cage is FR-0044, pending). |

`audit` uses its own scale: `0` all OK · `2` at least one `UNVERIFIED`/`BELOW_MIN` (or a
G-23 confirm-delete precondition refusal on drift) · `3` at least one `BROKEN`. `propose` uses
`0` pass / `2` gate failed.

> Some commands print flags with a **single dash** in their own help output (e.g. `-key`,
> `-out`). Both `-flag` and `--flag` are accepted. This manual reproduces flag names as the
> command prints them, and shows examples in the common `--flag` form.

---

## Command reference

### Lifecycle at a glance

```
keygen → pack → sign → verify-sig      # author, locally, fully offline
  → publish (admit) → attest           # governed distribution (registry)
  → trust add → install / verify       # consumer: pin, pull, verify offline
  → verify-hook (gate) → use           # runtime enforcement
  → audit → revoke                     # ongoing governance
```

---

### `keygen` — generate an author keypair

```bash
skillctl keygen --out PATH
```

Writes `<PATH>.priv` (mode `0600`) and `<PATH>.pub` (mode `0644`), both PEM-wrapped ed25519
(PKCS#8 private / SPKI public). Suggested location: `~/.config/m3c/skill-keys/<name>`.

| Flag | Purpose |
|------|---------|
| `-out` | Output keypair stem; produces `<out>.priv` and `<out>.pub`. **Required.** |

```bash
skillctl keygen --out ~/.config/m3c/skill-keys/mykey
```

Exit: `0` ok · `2` usage.

---

### `pack` — build a `.skb` bundle

```bash
skillctl pack --skill <dir> -o <out.skb> --name <n> --version <v> [options]
```

Packs a skill directory (which must contain `SKILL.md`) into a sealed `.skb` bundle with a
manifest. Data-scopes are validated **fail-closed at pack time**, before the digest is
computed, so the author signature covers them.

> `pack` does not implement `--help`; it prints `Unknown flag: --help` and then its usage.

| Flag | Purpose |
|------|---------|
| `--skill <dir>` | Skill directory containing `SKILL.md`. **Required.** |
| `-o, --output <path>` | Output `.skb` file. **Required.** |
| `--name <s>` | Skill name (manifest field). **Required.** |
| `--version <s>` | Skill version (manifest field). **Required.** |
| `--summary <s>` | One-line description. |
| `--source-repo <s>` / `--source-commit <sha>` / `--source-path <s>` | Provenance: where the skill came from. |
| `--author-intent green\|yellow\|red` | Advisory governance hint — **the verifier ignores it**; signed attestations bind. |
| `--author-intent-rationale <s>` | Free-text rationale for the intent. |
| `--compatibility <s>` | Compatibility note. |
| `--depends-on kind:name:constraint` | Declare a dependency, e.g. `python:requests:>=2.31`. Repeatable. |
| `--data-scopes <json>` | Typed SPEC-0196 data-scope, bound *into* `bundle.json`. Repeatable. Validated fail-closed. |
| `--data-dep <json>` | **Deprecated** alias for `--data-scopes`. |
| `--side-effects <list>` | Comma-separated SPEC-0196 §5 side-effect tokens (signed into intent). |
| `--destructive true\|false` | Author claim: irreversible changes (§3.3 cross-rule input). |
| `--network true\|false` | Author claim: outbound network (§3.3 cross-rule input). |

```bash
skillctl pack \
  --skill ./my-skill -o my-skill.skb \
  --name my-skill --version 1.0.0 \
  --summary "What this skill does" \
  --data-scopes '{"id":"ds:fs/cwd","kind":"local_fs","access":"write","scope":"<cwd>/decks/**","reason":"write deck"}'
```

Exit: `0` ok · `2` usage / validation error.

---

### `sign` — sign a bundle

```bash
skillctl sign BUNDLE.skb --key PATH.priv [--identity-id ID]
```

Computes the bundle's SHA-256 digest, signs the 32 raw digest bytes with ed25519, and writes
a **detached** signature: `<BUNDLE.skb>.<digest_hex>.author.sig` (64 raw bytes, mode `0644`).

| Flag | Purpose |
|------|---------|
| `-key` | Path to PEM PKCS#8 ed25519 private key (mode `0600`). **Required.** |
| `-identity-id` | Author identity ID (advisory; reserved for future use). |

```bash
skillctl sign my-skill.skb --key ~/.config/m3c/skill-keys/mykey.priv
```

Exit: `0` ok · `2` usage.

---

### `verify-sig` — verify a detached signature (offline)

```bash
skillctl verify-sig BUNDLE.skb --pubkey PATH.pub
```

Recomputes the bundle's digest, locates the matching `.author.sig`, and verifies it. **No
network, no CA.**

| Flag | Purpose |
|------|---------|
| `-pubkey` | Path to PEM SPKI ed25519 public key. **Required.** |

```bash
skillctl verify-sig my-skill.skb --pubkey ~/.config/m3c/skill-keys/mykey.pub
```

Exit: `0` ok · `11` signature invalid · `1` other error · `2` usage.

---

### `trust` — manage trust roots

```bash
skillctl trust <list|add|remove> [flags]
```

Manages `~/.claude/skill-trust-roots.yaml` (SPEC-0188 §4.4) — the registry keys you pin.
Multiple keys per registry are supported for rotation overlap windows. `rm` is an alias for
`remove`.

**`trust list`** — print configured registries and their pinned keys.

**`trust add`** — pin a registry public key.

| Flag | Purpose |
|------|---------|
| `-registry` | Registry URL (e.g. `https://aims.example.com/api/skills`). **Required.** |
| `-pubkey` | Path to PEM SPKI ed25519 public key file. **Required.** |
| `-id` | Optional key-id label (defaults to a short fingerprint-derived id). |

**`trust remove`** — unpin a registry (including all its keys).

| Flag | Purpose |
|------|---------|
| `-registry` | Registry URL to remove. **Required.** |

```bash
skillctl trust add --registry https://aims.example.com/api/skills --pubkey registry.pub
skillctl trust list
skillctl trust remove --registry https://aims.example.com/api/skills
```

`trust --help` also prints the shared verifier exit-code table (see [Exit codes](#exit-codes)).

---

### `install` — pull, verify, and install

```bash
skillctl install <name>[@<version>] [flags]
```

Pulls a bundle from the registry, runs the SPEC-0188 §7 verifier, and **atomically** installs
it under `~/.claude/skills/<name>/`. Refuses if *any* trust-chain step fails. `<version>` may
be a human version string (`1.0.0`) or a digest pin (`sha256:<hex>`); omit it to install the
newest admitted version.

| Flag | Purpose |
|------|---------|
| `-allow-yellow` | Lower the gate from green to yellow for this install (audited). |
| `-governance-min green\|yellow` | Override the trust-root's `governance_minimum`. Empty = use trust-root. |
| `-home` | Override the install root (advanced; defaults to `$HOME`). |
| `-ignore-deps` | Skip `depends_on` resolution (audited). |
| `-registry` | Registry base URL. Required only when trust-roots pins multiple registries. |
| `-tenant` | Pin this install to a tenant scope (§7 step 5.5). Overrides trust-roots `tenant_scope`. |
| `-timeout` | HTTP timeout for registry calls (default `30s`). |
| `-verbose` | Print structured per-step log lines to stderr. |

```bash
skillctl install my-skill@1.0.0
skillctl install my-skill@sha256:<hex> --verbose
```

Exit: `0`, `1`, `2`, `10`–`16` (see [Exit codes](#exit-codes)).

---

### `verify` — re-run the trust chain

```bash
skillctl verify <name> [flags]
skillctl verify --all [--quarantine]
skillctl verify --bundle <file.skb> [--trust-roots <file>] [--json]
```

Re-runs the SPEC-0188 §7 trust-chain check against an already-installed skill — useful for
catching post-install revocations or trust-root rotations. `--all` re-verifies everything.
`--bundle` verifies a **standalone `.skb` file** with no install state and no network, against
locally pinned trust-roots — the trustless third-party path (requires a `<file>.skbmeta.json`
sidecar or `--meta`).

| Flag | Purpose |
|------|---------|
| `-bundle` | Verify a standalone `.skb` file, fully offline against pinned trust-roots (SPEC-0276 R4.2). |
| `-meta` | Path to the BundleMeta envelope JSON for `--bundle` (default: the sidecar `.skbmeta.json`). |
| `-trust-roots` | Trust-roots YAML to use instead of the default. Pair with `--bundle` for a portable kit. |
| `-offline` | Network-free verify: use stashed metadata + bind on-disk content to the signed `.skb`. No registry calls. |
| `-revocations` | Signed revocation list to enforce offline for `--bundle`. Revoked digest → `17`; forged list → `12`. |
| `-checkpoint` | Signed freshness checkpoint (SPEC-0279 R4) to reset the `--revocations` staleness clock. Forged/untrusted → `12`; a rollback / too-old checkpoint that can't reset the clock leaves the snapshot stale → `22`. |
| `-emergency` | Signed emergency deny-list (SPEC-0279 R5). Named digest → `17`; forged list → `12`. |
| `-allow-yellow` | Permit a yellow result against a green-required trust root (does not re-audit). |
| `-governance-min green\|yellow` | Override the trust-root's `governance_minimum`. |
| `-home` | Override the install root. |
| `-json` | Emit the verification result as JSON (`--bundle` mode). |
| `-registry` | Registry base URL. Required only when trust-roots pins multiple registries. |
| `-tenant` | Pin this verify to a tenant scope (§7 step 5.5). |
| `-timeout` | HTTP timeout for registry calls (default `30s`). |
| `-verbose` | Print structured per-step log lines to stderr. |

```bash
skillctl verify my-skill
skillctl verify --all
skillctl verify --bundle my-skill.skb --trust-roots ./roots.yaml --json
```

Exit: same as `install` (see [Exit codes](#exit-codes)).

---

### `attest` — post a governance attestation

```bash
skillctl attest <bundle-digest> --level <green|yellow|red> \
  --rationale "<text>" --reviewer-id <id> --key <path> \
  [--registry <url>] [--timeout <duration>]
```

Composes the canonical attestation message
(`attestation\n<digest>\n<level>\n<attested_at>\n<reviewer_id>\n`), signs it with the given
ed25519 key, and POSTs it to `<registry>/attestations`.

| Flag | Purpose |
|------|---------|
| `-level green\|yellow\|red` | Governance verdict. **Required.** |
| `-rationale` | Free-text rationale (audit metadata; **not** folded into the signed bytes). **Required.** |
| `-reviewer-id` | Reviewer identity ID (e.g. `id:reviewer@m3c`). **Required.** |
| `-key` | PEM PKCS#8 ed25519 private key (mode `0600`). **Required.** |
| `-author-id` | Bundle author ID, for the SPEC-0246 §5 reviewer≠author check when the admit record is unavailable (offline). Optional. |
| `-registry` | Registry base URL (default `http://localhost:8080/api/skills`). |
| `-timeout` | HTTP request timeout (default `30s`). |

```bash
skillctl attest sha256:<hex> --level green --rationale "reviewed" \
  --reviewer-id id:reviewer@m3c --key ~/.config/m3c/skill-keys/reviewer.priv \
  --registry https://aims.example.com/api/skills
```

Exit: `0` ok · `1` generic/network/non-2xx · `2` usage.

---

### `revoke` — revoke an admitted bundle (and the kill-switch feed)

```bash
skillctl revoke <bundle-digest> --reason <code> [--registry <url>] [--timeout <duration>]
skillctl revoke feed [--status] [--refresh] [--registry <url>] [--tenant <T>]
```

Revokes an admitted bundle (SPEC-0188 §4.5) by publishing a **signed, offline-verifiable**
`BundleRevokedEvent` to the registry. The verifier then enforces it with freshness contracts
(SPEC-0279), failing **closed** on a stale or rolled-back list. `<bundle-digest>` is the
`sha256:<hex>` digest to revoke.

| Flag | Purpose |
|------|---------|
| `-reason key_compromise\|vulnerability\|governance_retraction\|author_request\|duplicate` | Reason code. **Required.** |
| `-actor-identity` | Revoke as a `governance_reviewer` (rather than the default `original_author`); pair with `--key`. |
| `-key` | Signing key for the revocation event. Required for the `original_author` (default) and `governance_reviewer` roles. |
| `-registry` | Registry base URL. |
| `-timeout` | HTTP request timeout. |

Three actor roles: **`original_author`** (the default — signs with the author key),
**`governance_reviewer`** (`--actor-identity` + `--key`), and **`registry_operator`**
(unsigned, operator-authenticated).

```bash
skillctl revoke sha256:<hex> --reason key_compromise --registry https://aims.example.com/api/skills
```

**`revoke feed` — the fleet kill-switch feed (FR-0045 D5).** A distinct, operator-facing mode:
it views or refreshes the signed **revocation HEAD** — a HEAD-aware, signed snapshot of the
current revocation set that the verifier fetches and enforces fail-closed. `feed` is
intercepted as the first argument **before** any digest parsing, so it is never mistaken for a
bundle digest.

| Flag | Purpose |
|------|---------|
| `-status` | **(default)** Fetch the signed revocation HEAD, verify it against the pinned registry key, and print its epoch / issued-at / staleness / counts — read-only; does **not** adopt it into the local cache. |
| `-refresh` | Run the revocation sweep now: fetch the latest signed HEAD **and adopt it** into the local cache + freshness anchor the gate reads. |
| `-registry` | Registry base URL. |
| `-tenant` | Scope the feed to a tenant. |

Because the HEAD is signed and checked against a **pinned** registry key, a MITM'd, mirrored,
truncated, rolled-back, replayed, or forged feed is rejected rather than trusted — this is the
transport-side, fail-closed kill-switch. It is **not** tamper-evident against a same-UID
compromised local process. Live fleet propagation of the HEAD is still rolling out; the offline
enforcement contract (a revoked digest → `17`, a stale snapshot → `22`) is built and testable
today.

```bash
skillctl revoke feed --status
skillctl revoke feed --refresh --registry https://aims.example.com/api/skills
```

Related paths: `publish --revoke` posts the same `BundleRevokedEvent` to your personal ER1
`self` registry (see [`publish`](#publish--admit--attest--revoke-via-er1-self-registry)), and
`agentid revoke` adds `agent:<id>` to a signed AgentID revocation list. All three produce
signed, offline-verifiable lists the verifier honours fail-closed.

---

### `audit` — antivirus-style verdict per skill

```bash
skillctl audit [flags]
```

Prints a per-skill verdict: `OK | UNVERIFIED | BROKEN | BELOW_MIN`. Cleanup is a G-23
destructive-op **two-step** (a signed dry-run token, then a confirm that re-checks the live
set). There is **no `--force`.**

| Flag | Purpose |
|------|---------|
| `-minimum-governance green\|yellow\|red` | Floor below which a skill is flagged. Defaults to trust-roots `governance_minimum`, else green. |
| `-format table\|json` | Output format (default: table on TTY, json on pipe). |
| `-source claude\|user\|plugins\|all` | Skill source scope. |
| `-include-shadowed` | Include shadowed skills (lower-tier names hidden by a higher-tier winner). |
| `-cleanup` | After listing, delete affected skills (gated; requires `--dry-run-cleanup` or `--confirm-delete`). |
| `-dry-run-cleanup` | **Step 1**: print the affected set + a signed 5-minute token; **no deletion**. |
| `-confirm-delete` | **Step 2**: actually delete; requires a fresh `--dry-run-cleanup-token`. |
| `-dry-run-cleanup-token <sig>` | The token from a prior `--dry-run-cleanup`. |
| `-keep-unverified` | Don't auto-clean `UNVERIFIED` skills under `--cleanup`. |

```bash
skillctl audit
skillctl audit --cleanup --dry-run-cleanup                                  # step 1: plan + token
skillctl audit --cleanup --confirm-delete --dry-run-cleanup-token <sig>     # step 2: re-check + delete
```

**The G-23 two-step contract.** Step 1 (`--cleanup --dry-run-cleanup`) computes the affected
set and prints a **signed token** (an HMAC bound to the hostname, the sorted affected skill
paths, and an issued-at timestamp) with a **5-minute** lifetime. It deletes nothing. Step 2
(`--cleanup --confirm-delete --dry-run-cleanup-token <sig>`) **re-computes the live affected
set and re-verifies the token against it.** If the set has **drifted** (a skill appeared,
disappeared, or changed) — or the token expired or was tampered — the confirm **refuses** and
exits `2` (a usage / precondition refusal), deleting nothing. Both the plan and the refusal
are auditable, and there is **no `--force`** to bypass the re-check: a destructive op that no
longer matches its approved plan simply does not run.

Exit: `0` all OK · `2` ≥1 `UNVERIFIED`/`BELOW_MIN`, **or** a confirm-delete precondition
refusal (drift/expiry/tamper) · `3` ≥1 `BROKEN`.

---

### `publish` — admit / attest / revoke via ER1 (`self` registry)

```bash
skillctl publish <name[@ver]> [flags]
skillctl publish --attest <name[@ver]> --level green --rationale '<why>' [flags]
skillctl publish --revoke <name> --digest sha256:<hex> --reason '<code>' [flags]
```

Publishes to your personal ER1 `self` registry (SPEC-0225). Three modes: admit a bundle
(default), post a governance attestation (`--attest`), or post a `BundleRevokedEvent`
(`--revoke`). `--all` batches an admit+attest for every entry in the publish manifest.

| Flag | Purpose |
|------|---------|
| `-attest` | Mode: publish an `AttestationPublishedEvent` instead of admitting. |
| `-revoke` | Mode: publish a `BundleRevokedEvent`. Requires `--digest` and `--reason`. |
| `-all` | Publish every entry in `--manifest` (admit + attest as one batch). |
| `-bundle` | Path to a pre-built `.skb`. If empty, the skill dir is packed in place. |
| `-skill-dir` | Skill directory. Default: `~/.claude/skills/<name>`. |
| `-version` | Skill version (overrides SKILL.md frontmatter). Required for admit. |
| `-digest` | `[--attest\|--revoke]` existing bundle digest (`sha256:<hex>`). Derived from `--bundle` if empty. |
| `-level green\|yellow\|red` | `[--attest]` governance level (default `green`). |
| `-rationale` | `[--attest\|--revoke]` one-line rationale. |
| `-reason` | `[--revoke]` short reason code (e.g. `key-compromise`, `deprecated`). |
| `-registry` | Registry spec: `self` (recommended) or `er1://…`. HTTP registries route through `install`. Default `self`. |
| `-er1-target prod\|stage\|local` | ER1 target (default `prod`). |
| `-er1-context` | ER1 context (default `skills`). |
| `-identity` | Author/registry identity id stamped into the event and tags. |
| `-key` | ed25519 private key (PEM PKCS#8). Default `$SIGNING_KEY_LOCATION` or `~/.config/m3c/skill-registry-self.key`. |
| `-manifest` | Publish manifest (with `--all`; default `INFRA/skill-registry/self/publish-manifest.txt`). |
| `-share-room <label>` | Map the bundle into a SPEC-0096 co-learning room. Repeatable. |
| `-inline-max` | Inline base64 cap; larger bundles need a claim-check (default `262144`). |
| `-no-checkpoint` | Don't append a checkpoint to the open SPEC-0213 session. |
| `-no-runbook-publish` | Don't auto-register the skill's runbook into the THOH catalog (SPEC-0275). |
| `-dry-run` | Print the plan + rendered item body; don't POST or pack. |
| `-yes` | Skip the 🟡 confirm pause (scripted runs). |

```bash
skillctl publish my-skill --bundle my-skill.skb --version 1.0.0
skillctl publish --attest my-skill --level green --rationale "reviewed"
skillctl publish --revoke my-skill --digest sha256:<hex> --reason superseded
```

Exit: `0` ok · `2` usage.

---

### `pull` — the 5-gate gauntlet against `self`

```bash
skillctl pull [flags]
```

Runs the 5-gate trust gauntlet against your `self` registry and stages verified bundles.
`--install` writes them under `~/.claude/skills/<name>/` (with a provenance sidecar);
installing is a G-23 two-step (`--dry-run-install` → `--confirm-install`).

| Flag | Purpose |
|------|---------|
| `-install` | Install verified bundles into `~/.claude/skills/<name>/` with a provenance sidecar. |
| `-trust-mode` | Required for `--install`: re-affirm the trust-mode path (writes `.m3c-provenance.json`). |
| `-dry-run-install` | G-23 step 1: print the create/overwrite plan + a token; do not write. |
| `-confirm-install` | G-23 step 2: consume `--dry-run-install-token` and write. |
| `-dry-run-install-token` | Token returned by `--dry-run-install`; required if any skill would be overwritten. |
| `-allow-downgrade` | Allow installing an older version over a newer one. |
| `-skill` | Filter: only this skill name. |
| `-digest` | Filter: only this exact bundle digest (`sha256:<hex>`). |
| `-since` | Best-effort lower bound on `occurred_at` (RFC3339). |
| `-skills-dir` | Where to install skills. Default `~/.claude/skills`. |
| `-trust-roots` | SPEC-0225 trust-roots YAML. Default `~/.claude/trust-roots.yaml`. |
| `-registry self` | Registry spec. Only `self` / `er1://…` here; HTTP routes through `install`. |
| `-er1-target prod\|stage\|local` / `-er1-context` | ER1 target/context (defaults `prod` / `skills`). |
| `-emit-installed` | After install, POST a `BundleInstalledEvent` so the other machine sees it. |
| `-identity` / `-key` | `[--emit-installed]` identity + signing key for the install event. |
| `-no-checkpoint` | Don't append a SPEC-0213 session checkpoint after install. |
| `-verbose` | Print one line per per-gate decision. |

```bash
skillctl pull --verbose
skillctl pull --install --trust-mode --dry-run-install
skillctl pull --install --trust-mode --confirm-install --dry-run-install-token <sig>
```

Exit: `0` ok · `2` usage.

---

### `registry` — inspect the `self` registry

```bash
skillctl registry <ls|show> [flags]
```

**`registry ls`** — list bundles in the `self` registry, grouped by skill.
Flags: `[--latest] [--skill <name>] [--er1-target …] [--er1-context …]`.

**`registry show`** — show the full event timeline (admit / attest / revoke / install) for
one skill or one digest.
Usage: `registry show <name | sha256:<hex>> [--er1-target …] [--er1-context …]`.

```bash
skillctl registry ls --latest
skillctl registry show my-skill
skillctl registry show sha256:<hex>
```

---

### `verify-hook` — the fail-closed Claude Code gate

```bash
skillctl verify-hook
```

A `PreToolUse(Skill)` hook: it reads a hook event on **stdin**, verifies the SPEC-0188 §7
chain, and emits an allow/deny decision as JSON on stdout. **Fail-closed** — if it cannot read
or verify the event, it denies. Wire it in your Claude Code settings as a hook; do **not** run
it by hand. Running it interactively prints a fail-closed deny (unreadable stdin) and exits
`2`.

**Revocation freshness is fail-closed at the gate too (FR-0045 D4).** Beyond the trust chain,
the hook enforces the SPEC-0279 freshness contract: an **emergency deny**, or a revocation
snapshot too stale to trust for the requested action (`bundle_revocation_stale` /
`agent_revocation_stale`, SPEC-0279 R3/R5), denies rather than allows. The hook **process**
always exits `2` to block the tool call; the deny message carries the underlying
`refusal_code` — `17` (revoked / emergency deny) or `22` (revocation snapshot stale). This is
the runtime edge of the FR-0045 kill-switch: because the revocation HEAD is checked against a
pinned registry key, a tampered, rolled-back, or forged feed is refused, not silently trusted.

```json
// settings.json (excerpt) — wire it as a PreToolUse(Skill) hook
{ "hooks": { "PreToolUse": [ { "matcher": "Skill", "hooks": [ { "type": "command", "command": "skillctl verify-hook" } ] } ] } }
```

---

### `gate-stats` — summarise gate decisions

```bash
skillctl gate-stats [--since <168h|YYYY-MM-DD>] [--json]
```

Summarises `gate-audit.jsonl`: decisions, top blocks, cache-hit rate.

| Flag | Purpose |
|------|---------|
| `-since` | Only events newer than this — a Go duration (e.g. `168h`) or a date (`YYYY-MM-DD`). |
| `-json` | Emit the summary as stable JSON. |

```bash
skillctl gate-stats --since 168h
skillctl gate-stats --since 2026-06-01 --json
```

---

### `agentid` — offline-verifiable agent identity

```bash
skillctl agentid <issue|verify|show|revoke> [flags]
```

An **AgentID** is an owner-signed mandate (SPEC-0277): *this agent may use these skills for
these intents*. It verifies **offline** against pinned owner/approver keys.

**`agentid issue`** — build + owner-sign a mandate.

| Flag | Purpose |
|------|---------|
| `--owner <plm-id>` / `--owner-key <path>` | Owner identity and signing key. |
| `--for-agent <ref>` | The agent instance the mandate is issued to. |
| `--skills a,b` | Granted skills. |
| `--intents x,y` | Granted intents. |
| `--data-scopes s,t` | Optional granted data-scopes. |
| `--approver <id>` / `--approver-key <path>` | Optional co-signing approver (raises the approver floor). |
| `--limit k=v` | Repeatable grant limits. |
| `--display-name N` / `--agent-id <id>` / `--trust-root URL` | Optional metadata. |
| `--expires <RFC3339>` | Expiry (e.g. `2026-12-31T00:00:00Z`). |
| `--out <file>` | Write the mandate JSON (e.g. `agentid.json`). |

**`agentid verify`** — verify a mandate offline.

| Flag | Purpose |
|------|---------|
| `--bundle <agentid.json>` | The mandate to verify. |
| `--offline` | Network-free verification. |
| `--trust-roots <file>` / `--registry <url>` | Pinned keys / registry disambiguation. |
| `--revocations <file>` / `--checkpoint <file>` / `--emergency <file>` | Signed lists enforcing SPEC-0279 freshness. |
| `--json` | Emit the result as JSON. |

**`agentid show`** — print owner, grant, expiry, fingerprints, signatures:
`skillctl agentid show <agentid.json>`.

**`agentid revoke`** — add `agent:<id>` to a signed, offline revocation list (SPEC-0276):
`skillctl agentid revoke <agent-id> --reason <text> --registry <url> [--key <path>] [--out <list.json>] [--epoch N]`.

```bash
skillctl agentid issue --owner id:you@m3c --owner-key mykey.priv \
  --for-agent agent-42 --skills my-skill --intents summarize --out agentid.json
skillctl agentid verify --bundle agentid.json --offline
skillctl agentid show agentid.json
skillctl agentid revoke agent-42 --reason compromised --registry https://aims.example.com/api/skills
```

Exit (`verify`): `0` ok · `11` owner-sig/not-pinned · `20` approver-floor · `21` expired ·
`17` revoked/emergency · `12` registry-not-pinned · `22` revocation-stale · `1` other.

---

### `translog` — L1 transparency log

```bash
skillctl translog <append|sth|prove|verify|consistency|witness> [flags]
```

A local RFC-6962 Merkle log (SPEC-0278, stdlib-only). L1 makes equivocation/withholding
**detectable**, not impossible. Event *data stays off the log* — only the signed event's
digest is appended. The default log file is `~/.claude/skillctl/transparency-log.jsonl`
(`--log` to override; `--log-id` default `skillctl-local`).

**`translog append`** — append an event.
`skillctl translog append <type> <digest> [--subject S] [--log PATH] [--log-id ID]`
where `type` ∈ `admit | attest | revoke | agentid-issue | agentid-revoke` and `digest` is
`sha256:<64 lowercase hex>` of the already-signed event.

**`translog sth`** — show / sign the current tree head.

| Flag | Purpose |
|------|---------|
| `-key` | Log ed25519 private key (PEM). If set, sign the head into an STH. |
| `-log` / `-log-id` | Log path / id. |

**`translog prove`** — emit an offline inclusion receipt.
`skillctl translog prove <digest> --key PATH.priv [--out FILE]` (`-key` **required**; `-out`
defaults to stdout).

**`translog verify`** — offline inclusion check.
`skillctl translog verify --receipt FILE --log-pubkey PATH.pub` (both **required**).

**`translog consistency`** — verify append-only between two heads.

**`translog witness`** — cross-witness STHs for a split view.
`skillctl translog witness --sths FILE --log-pubkey PATH.pub` (both **required**).

```bash
skillctl translog append admit sha256:<hex> --subject my-skill
skillctl translog sth --key ~/.config/m3c/skill-keys/log.priv
skillctl translog prove sha256:<hex> --key ~/.config/m3c/skill-keys/log.priv --out receipt.json
skillctl translog verify --receipt receipt.json --log-pubkey log.pub
skillctl translog witness --sths sths.json --log-pubkey log.pub
```

Exit: `translog verify` → `0` ok · `23` not-included · `1` other · `2` usage.
`translog witness` → `0` consistent · `24` split-view-detected · `1` other · `2` usage.

---

### `session` — session-state in ER1 (SPEC-0213)

```bash
skillctl session <open|checkpoint|close|resume|list|show> [flags]
```

Persists the working session as an ER1 item and appends checkpoints; resume it on any machine.
All verbs share one flag-set (only some flags apply per verb).

| Verb | Purpose |
|------|---------|
| `open` | Create the session-state item for this session (idempotent). |
| `checkpoint` | Append a checkpoint child item (`--auto` for a git/todo snapshot). |
| `close` | Write a final close-checkpoint (`--summary` verbatim, or `--distill`). |
| `list` | List session-state items (`--project` / `--host` / `--open-only`). |
| `show` | Show a session-state item by `session_id` or `doc_id`. |
| `resume` | Print a resume hint for a prior session. |

| Flag | Purpose |
|------|---------|
| `-session` | Session id (the harness `session_id`; required for checkpoint/close). |
| `-C` | Resolve the project context relative to this directory. |
| `-project` | PLM project id override (default: from `.m3c/project.yaml`). |
| `-er1-target prod\|local\|stage\|<url>` / `-er1-context` | ER1 target / context override. |
| `-intent` | Session intent (open only). |
| `-continues <ctx>/<doc_id>` | Thread the chain to a prior session-state item (open only). |
| `-model` | Agent/model recorded as `opened_by` (default `skillctl`). |
| `-auto` | Checkpoint: build a git-diff/todo snapshot rather than prose (skips if nothing changed). |
| `-note` | Checkpoint note prose. |
| `-todos` | Open-items text for the checkpoint body. |
| `-summary` | Close summary (verbatim — your words). |
| `-distill` | Close: mark the close-checkpoint `auto:generated` (agent-authored summary, SPEC-0210). |
| `-host` | Filter by host (list/resume). |
| `-open-only` | List: exclude closed sessions. |
| `-latest` | Resume: pick the newest session (default true when only one matches). |

```bash
skillctl session open --intent "port whisper"
skillctl session checkpoint --session <id> --auto
skillctl session close --session <id> --summary "shipped v0.4.0"
skillctl session list --open-only
skillctl session resume --latest
```

---

### `project` — PLM project context (SPEC-0214)

```bash
skillctl project <show|resolve|channels|path> [-C dir] [--field name] [--kind kind]
```

Resolves the PLM project context for the current directory from `.m3c/project.yaml` (falling
back to a directory-slug when there is no descriptor).

| Verb | Purpose |
|------|---------|
| `show` | Print the resolved context (project id, ER1 target/context, descriptor source). |
| `resolve` | Print one field: `--field project_id\|er1-target\|er1-context\|channel:<kind>\|…`. |
| `channels` | List the v2 `channels:` block (`--kind` to filter). |
| `path` | Print the descriptor file path, or `(none)`. |

```bash
skillctl project show
skillctl project resolve --field project_id
skillctl project channels --kind repo
skillctl project path
```

---

### `awareness` — the admission bridge (SPEC-0195)

```bash
skillctl awareness <sync|verify|reset> [flags]
```

**`awareness sync`** — admit local skills to a registry by scanning (or reading a saved scan).
Default is dry-run; pass `--confirm` to actually POST. Registry resolution:
`--registry` > trust-roots `default_registry` > `$M3C_REGISTRY_URL`.

| Flag | Purpose |
|------|---------|
| `-confirm` | Required to actually push to the registry (defends against accidental writes). |
| `-dry-run` | Build the envelope; do not POST. |
| `-source claude\|user\|plugins\|all` | Scan source (default `claude`; ignored if `--inventory` is set). |
| `-inventory <file\|->` | Read scan JSON from FILE; `-` reads stdin. |
| `-registry` | Registry URL override. |
| `-key` | Author key path (PEM PKCS#8). Default `~/.claude/skillctl-keys/author.key`. |
| `-author-identity` | Override the author identity. |
| `-require-intent` | Refuse entries with no intent or the SPEC-0196 `UNKNOWN` sentinel. |
| `-default-intent yellow\|green` | Stamp this level on entries with no/UNKNOWN intent (empty = off). |
| `-default-attest yellow\|green\|none` | After admission, request a default attestation (default `none`). |
| `-session` | Session tag (default `skill-awareness/<host>/<YYYY-MM-DD>`). |
| `-help-advanced` | Print advanced flags (e.g. `--allow-overwrite`). |

**`awareness verify`** — read back per-session admissions.
Usage: `skillctl awareness verify [--session TAG] [--registry URL]`.

**`awareness reset`** — delete admit-from-scan docs scoped to a `session_tag` (G-23 two-step).

```bash
skillctl awareness sync --source claude --dry-run
skillctl awareness sync --confirm --require-intent
skillctl awareness verify --session skill-awareness/host/2026-07-02
```

---

### `intent` — declare / show a bundle's SPEC-0196 intent

```bash
skillctl intent <declare|show> [flags]
```

**`intent declare <skill-name|@digest>`** — patch the `intent` block of a previously-admitted
bundle, replacing the awareness `UNKNOWN` sentinel with a real declaration. Requires
`--confirm` to issue the PATCH; typed data-scope via `--data-scopes` (repeatable JSON).
Exit codes: `0` ok · `1` generic/network · `2` usage · `18` intent inconsistent with
`data_dependencies` (SPEC-0196 §3.3).

**`intent show <skill-name|@digest> --registry URL`** — print the declared intent +
`data_dependencies`. A scope is shown as **AUTHORITATIVE** only when the local `.skb`'s author
signature is verified against a **pinned** trust-root key (`--bundle` + the full verify
chain); a bare digest match is `UNVERIFIED`. `--json` for machine output.

```bash
skillctl intent show my-skill --registry https://aims.example.com/api/skills
skillctl intent declare my-skill --data-scopes '{"id":"…","kind":"local_fs","access":"read","scope":"…","reason":"…"}' --confirm
```

---

### `propose` — the ready-to-promote gate (SPEC-0194)

```bash
skillctl propose <skill-name> [flags]
```

Runs the SPEC-0194 §6 ready-to-promote gate against a local skill and, on pass, registers a
proposal record so the post-admission hook can flip `pending → admitted` when the bundle is
admitted.

| Flag | Purpose |
|------|---------|
| `-intent green\|yellow\|red` | Author governance intent. |
| `-rationale` | Required for yellow/red intent. |
| `-dry-run` | Run the gate only; do not POST a proposal record. |
| `-bug-reports-dir` | Enable gate check #8 (open BUG-NNNN against this skill). |
| `-last-admitted-version` | Enable gate check #10 (proposed version > last admitted). |
| `-skip-smoke` | Skip gate check #9 (smoke-test marker). |
| `-bodyscan-rationale` | Justify a 🟡 bodyscan verdict (check #11); a 🔴 verdict cannot be overridden. |
| `-proposal-id` | Client-generated proposal id (ULID). Default: locally generated. |
| `-registry` | Registry base URL (default `http://localhost:8080/api/skills`). |

Exit: `0` gate passed (or `--dry-run`) · `2` gate failed (one or more rows print `FAIL`).

---

### `export-verification-kit` — portable, trust-nothing kit (SPEC-0276)

```bash
skillctl export-verification-kit --bundle <file.skb> --out <dir> [flags]
```

Builds a portable, offline verification kit that a third party can check with no network and
no trust in you.

| Flag | Purpose |
|------|---------|
| `-bundle` | Signed `.skb` to package. **Required.** |
| `-out` | Output directory for the kit. **Required.** |
| `-meta` | BundleMeta envelope JSON (default: sidecar `.skbmeta.json`). |
| `-trust-roots` | Trust-roots YAML to source pinned keys from. Must be pinned mode. |
| `-revocations` | Optional signed revocation list to include (validated against the pinned key before inclusion). |
| `-registry` | Registry URL to disambiguate when trust-roots pins multiple. |
| `-zip` | Also produce `<out>.zip`. |

```bash
skillctl export-verification-kit --bundle my-skill.skb --out ./kit --zip
```

---

### `compliance` — offline evidence aid (SPEC-0276)

```bash
skillctl compliance report --framework <eu-ai-act|nist-ai-rmf|soc2> [--format md|json] [--out file]
```

Generates an **offline evidence aid** mapping your installed skills' trust posture to a
framework's controls. This produces *evidence*, **not** a certification.

| Flag | Purpose |
|------|---------|
| `-framework eu-ai-act\|nist-ai-rmf\|soc2` | Framework. **Required.** |
| `-format md\|json` | Output format (default `md`). |
| `-out` | Write to file instead of stdout. |
| `-skills-dir` / `-home` | Skills directory / home override. |
| `-offline` | Offline mode (default and only mode in v1). |

```bash
skillctl compliance report --framework eu-ai-act --format md --out evidence.md
```

---

### `login` — ER1 device pairing (FR-0043)

```bash
skillctl login [--no-browser] [--timeout 5m] [--base-url URL]
skillctl login --status | --logout
```

Browser device-pairing against ER1; saves a token `skillctl` uses automatically for
registry-backed commands. Shares the ER1 login with `m3c-tools`.

| Flag | Purpose |
|------|---------|
| `-base-url` | ER1 server base URL. Default: public SaaS (`https://onboarding.guide`), or `ER1_API_URL` if set. |
| `-no-browser` | Print the login URL but do not open a browser (headless/SSH). |
| `-timeout` | How long to wait for the browser callback (default `5m0s`). |
| `-status` | Report whether a (non-expired) device token is stored, and exit. |
| `-logout` | Remove the stored device token and exit. |

```bash
skillctl login
skillctl login --status
skillctl login --logout
```

---

### `version` / `help`

```bash
skillctl version     # print the build version
skillctl help        # the grouped command map
```

Any command accepts `--help` (some sub-verbed groups print usage on the bare parent, e.g.
`skillctl agentid --help`, `skillctl translog`).

---

### Other commands (one-line synopsis)

Derived from each command's own usage output.

| Command | Synopsis |
|---------|----------|
| `scan` | Scan skill directories (`~/.claude/skills`, plugin skill dirs, …) and emit a JSON inventory. |
| `report` | Render a scan into a report. `skillctl report [--format html\|md] --input <scan.json> [--out <file>]`. |
| `diff` | Diff two scans. `skillctl diff <scan1.json> <scan2.json> [--output json\|md\|html\|text] [--out <file>]`. |
| `seal` | Snapshot all installed skills into a signed inventory seal (under `~/.m3c-tools/skill-seals/`). |
| `import` | Import a scan into a remote target. `skillctl import --target <url> [--api-key <key>] [--input <scan.json>] [--dry-run]`. |
| `menubar` | Launch the macOS menu-bar app surface (interactive; long-running). |
| `review` | Review installed / scanned skills. |
| `browse` | Build a local skill graph and serve an interactive browser at `http://127.0.0.1:<port>/?token=…`. |
| `consolidate` | Report duplicate / orphan / drifted / missing-frontmatter skills across projects. |
| `sync-usage` | Sync local skill-usage counters to ER1 (needs `--api-key`, `M3C_API_KEY`, or `~/.m3c-tools/er1_session.json`). |
| `runbook` | `skillctl runbook publish <runbook.html> --tag <tag> [flags]` — publish an onboarding runbook into the THOH catalog (SPEC-0272/0275). |
| `room` | `skillctl room <share\|unshare> <skill> --room <label> [flags]` — share/unshare a skill into a SPEC-0096 co-learning room. |

> `scan`, `report`, `diff`, `seal`, `import`, `menubar`, `review`, `browse`, `consolidate`,
> `sync-usage` do not implement `-h`/`--help`; run them with no arguments to see their usage,
> or consult the flags shown above. Run `skillctl <cmd> --help` for the current flags on the
> other commands.

---

## Files & locations

| Path | Contents |
|------|----------|
| `~/.claude/skill-trust-roots.yaml` | Pinned registry public keys (managed by `trust`). The root of the offline verification chain. |
| `~/.claude/skills/<name>/` | Installed skills (`install`, `pull --install`). Installs are atomic. |
| `<stem>.priv` (mode `0600`) / `<stem>.pub` (mode `0644`) | ed25519 keypair written by `keygen`, PEM PKCS#8 / SPKI. |
| `<bundle>.<digest_hex>.author.sig` | Detached author signature written by `sign` (64 raw bytes, mode `0644`). |
| `~/.claude/skillctl/transparency-log.jsonl` | Default L1 transparency log (`translog`; `--log` to override). |
| `gate-audit.jsonl` | Append-only audit log of `verify-hook` decisions, summarised by `gate-stats`. |
| `~/.m3c-tools/skill-seals/` | Inventory seals written by `seal`. |
| `.m3c/project.yaml` | SPEC-0214 PLM project descriptor resolved by `project` (and by `publish`/`session`). |
| `~/.config/m3c/skill-registry-self.key` | Default `self`-registry signing key for `publish` / `pull` (or `$SIGNING_KEY_LOCATION`). |

ER1 credentials for registry-backed commands resolve via Keychain → Secret Manager → env
(ADR-0003), keyed by the ER1 target.

---

## See also

- **[Quickstart: skillctl](quickstart-skillctl.md)** — the happy path in five minutes.
- **[Manual: m3c-tools](manual-m3c-tools.md)** — the memory-capture toolkit `skillctl` ships alongside.
