---
layout: default
title: Manual: skillctl
---

# Manual: skillctl

`skillctl` is the trust-and-governance CLI for agent skills. Every skill gets a verifiable
identity and a full lifecycle, **author → pack → sign → admit → attest → verify / install →
use → audit → revoke**, so nothing an agent runs is unauthorized or unprovable. The
trust-chain check is **offline-verifiable: no external authority sits in the verification
path.** A hosted registry, ledger, or transparency log is *complementary*, not required to
prove a bundle authentic.

> **New here?** The [Quickstart: skillctl](../../old/quickstart-skillctl.md) walks the happy path in
> about five minutes. This manual is the exhaustive reference: every command, every flag,
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

See the [Quickstart](../../old/quickstart-skillctl.md#1-install) for one-line install commands per
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
| **Trust roots** | The registry public keys *you* have pinned; the verifier trusts only these. There are **two files, one per registry model**: `~/.claude/skill-trust-roots.yaml` (HTTP registries, managed by `trust`) and `~/.claude/trust-roots.yaml` (the ER1 `self` registry, hand-written). See [Trust roots & registries: which file, when](#trust-roots--registries--which-file-when). |
| **Registry** | Where admitted bundles and their governance events live; it can be `self` ER1 registry (personal) or an HTTP registry. The registry is a *distribution + audit* surface. It is **not** in the cryptographic verification path. |
| **Admit / attest** | *Admit* publishes a bundle to a registry. *Attest* posts a signed governance verdict on an admitted digest. Attestations, not author intent, are what bind governance. |
| **Governance level (green/yellow/red)** | The verdict carried by an attestation. Install/verify enforce a configurable minimum (default green). Author *intent* is advisory; the verifier ignores it. |
| **Revocation + freshness** | A signed, offline-verifiable revocation list. Freshness contracts (SPEC-0279) fail **closed**: a stale, rolled-back, or forged revocation list is rejected rather than silently trusted. A signed checkpoint can reset the staleness clock; a signed emergency deny-list denies a named digest immediately. |
| **AgentID** | An owner-signed *mandate* stating that a specific agent instance may use these skills for these intents. It verifies **offline** against pinned owner/approver keys: no authority in the path. |
| **Transparency log (translog)** | A local RFC-6962 Merkle log (SPEC-0278, "L1"). It makes equivocation and withholding **detectable**, and emits offline inclusion receipts. It does not gate installs; L2 (BFT ledger) and L3 (public anchoring) are deferred. |
| **The fail-closed gate** | `verify-hook` is a Claude Code `PreToolUse(Skill)` hook. It verifies the trust chain before any skill runs and emits allow/deny. If it cannot read or verify, it **denies**: fail-closed. |

---

## Trust roots & registries: which file, when

skillctl has **two** trust-roots files, one per registry model. Using the wrong one is the
most common setup error, so pick deliberately:

| You are using… | Trust-roots file | Created by | Read by |
|----------------|------------------|------------|---------|
| **ER1 `self`** (`publish` / `pull --registry self`) | `~/.claude/trust-roots.yaml`, flat: `registry: self`, `pubkey_b64`, `fingerprint`, `governance_minimum` | **hand-written / carried out-of-band** | `pull` |
| **HTTP `/api/skills` registry** | `~/.claude/skill-trust-roots.yaml` | `skillctl trust add --registry <URL> --pubkey <path>` | `install`, `verify`, `audit` |

- `skillctl trust add --registry` takes a **URL** (e.g. `https://aims.example.com/api/skills`),
  **never** an ER1 context id. It writes `skill-trust-roots.yaml`.
- The ER1 `self` consumer path does **not** use `trust add`: hand-write `trust-roots.yaml`
  and verify its `fingerprint` out-of-band before the first `pull`.
- **Keys:** `keygen --out P` writes `P.priv` + `P.pub`. Pass the private key explicitly to
  `sign` / `publish` as `--key P.priv`; the `self` default `~/.config/m3c/skill-registry-self.key`
  applies only when `--key` is omitted.

For the full two-person walkthrough over ER1, see
**[Acceptance & Handover: the skill lifecycle](../betrieb/acceptance-skillctl-lifecycle.md)**.

---

## Exit codes

`install`, `verify`, `verify-sig`, `pull` and the gates return **numbered** exit codes so
automation can branch precisely. Two tables follow, and `cmd/exitaudit` checks both against
`pkg/skillctl/exitcode` on every run of `scripts/check-docs.sh`: the first IS the register,
the second lists the numbers that live outside it.

What the gate reads, exactly: the `Exit:` statement under each command below, and the
Exit-Code cells of [docs/v2/referenz/CLI-VERBS.md](CLI-VERBS.md). Every number in those two places must
appear in one of the two tables, so a code cannot be documented there without first saying
where it comes from. Numbers in ordinary prose, and the numbers in the `verify-hook`
`refusal_code` table, are **not** scanned; a wrong number in either would not turn the gate
red, and both were measured going through green on 2026-09-07. `cmd/exitaudit` prints its own
reach on every run, including how many verb rows state no `Exit:` line and are therefore never
compared against the register.

The **base space** is shared by every command: `0` ok, `1` generic error (network and
non-2xx included), `2` usage or flag error. The three `PreToolUse` gates (`verify-hook`,
`enforce`, `guard-path`) always exit `2` to block the tool call and carry their specific
number in the decision's `refusal_code`, never in the process status. Codes that share a
number share a theme (FR-0023), which is what lets a script branch on the number alone.

### The register

<!-- Generated block: run `go run ./cmd/exitaudit -write` after changing the register. -->
The Code, Label, Surface and Theme columns come from `exitcode.AllCodes()`; only the
Meaning column is written by hand, and `exitaudit -write` carries it forward. Editing the four
generated columns by hand turns `check-docs.sh` red.

<!-- exitaudit:register:begin -->

| Code | Label | Surface | Theme | Meaning |
|-----:|-------|---------|-------|---------|
| `3` | `need_priv_msg` | `pin` | privileged write required | `pin install` staged the merged managed-settings file and printed a runbook. Nothing was written; re-run the printed command with administrator rights. |
| `4` | `pin_required` | `import-public` | input validation | The import source carried no pin. Pin the exact commit or digest and retry. SPEC-0201; the surface is not built in this tree. |
| `5` | `scanner_refuse` | `import-public` | scanner / policy | The scanner refused the imported skill. Read the finding; retrying unchanged cannot help. |
| `6` | `bundle_revoked` | `pull` | trust-chain revocation | Every skipped bundle failed the revocation gate: a `BundleRevokedEvent` exists for that digest. Never retry. Run `skillctl verify --all` to refresh and quarantine. |
| `7` | `no_matches` | `pull` | query yielded nothing | TODO: say what an operator should DO about it. |
| `10` | `digest_mismatch` | `verify` | trust-chain digest | The bytes are not the bytes that were signed. Also what `verify-sig` returns for an altered bundle, and what `pull --install` returns when the `CHECKSUMS` manifest stops describing the contents. Ask the publisher to repack and re-sign; this is not a transport fault. |
| `11` | `sig_invalid` | `signing` | trust-chain signature | `verify-sig` could not verify the detached author signature with the key you gave it. Check you used the AUTHOR's public key. |
| `11` | `author_sig_invalid` | `verify` | trust-chain signature | The author signature over the bundle does not verify. Same cause, reached through the §7 chain. |
| `12` | `registry_not_trusted` | `verify` | trust-chain registry-root | The registry key is not in your trust roots. Pin it: `trust add` over HTTP, `trust-roots.yaml` for `self`. |
| `13` | `governance_below_min` | `verify` | policy governance | No attestation meets the governance floor. Post a green attestation, or lower the floor deliberately. |
| `14` | `deps_unsatisfied` | `verify` | policy dependency | A `depends_on` entry is absent or below its floor. Install the dependency first. |
| `15` | `blob_missing` | `verify` | trust-chain blob | The registry lists the bundle but the blob does not fetch. A transport or registry fault, so retrying is reasonable. |
| `16` | `tenant_blocked` | `verify` | policy tenant | The CISO console blocked this bundle for your tenant. |
| `17` | `no_source_policy` | `import-public` | data-source / source-policy | No source policy admits the origin. SPEC-0201; the surface is not built in this tree. |
| `17` | `identity_revoked` | `revoke` | data-source / source-policy | The author identity is revoked, so the bundle's provenance chain is refused (SPEC-0198 §11). Surfaced by `verify` and `install`, not by `revoke` itself. |
| `17` | `data_source_denied` | `verify` | data-source / source-policy | A declared data source is denied by policy. Also the `refusal_code` a gate carries for a revoked bundle or an emergency deny. |
| `18` | `intent_capped` | `import-public` | intent contradiction | The declared intent was capped on import. SPEC-0201; the surface is not built in this tree. |
| `18` | `intent_inconsistent` | `verify` | intent contradiction | The declared intent contradicts `data_dependencies` (SPEC-0196 §3.3). Emitted by `intent declare` and by `pack`. |
| `19` | `source_blocked` | `import-public` | identity / source-block | The import source is blocked. SPEC-0201; the surface is not built in this tree. |
| `19` | `identity_mismatch` | `verify` | identity / source-block | `client_identity` is not `admitted_by_identity`, the refusal `awareness reset` gives. |
| `20` | `self_attested` | `verify-chain` | attestation reviewer-independence | The attestation's reviewer IS the author (`reviewer_id` equals `author_id`), so the floor is not met independently (SPEC-0246 §5.2). |
| `21` | `agentid_expired` | `agentid` | agent-identity expiry | The AgentID mandate is past its expiry. Re-issue it. |
| `22` | `revocation_stale` | `verify-chain` | revocation freshness | The revocation snapshot is too old to trust for this action, and the answer fails closed (SPEC-0279 R3, FR-0045 D4). Run `skillctl revoke feed --refresh`. |
| `23` | `not_included` | `translog` | log inclusion | `translog verify`: the receipt does not verify against the log head. |
| `23` | `inclusion_missing` | `verify-chain` | log inclusion | The chain carries no transparency-log inclusion proof (SPEC-0278 L1). |
| `24` | `split_view` | `translog` | log equivocation | `translog witness` saw two signed tree heads that cannot both be true. |
| `25` | `offline_unverifiable_managed` | `state-machine` | offline / no-policy-basis | A `refusal_code`, not a process exit. A legacy managed install with no offline metadata, while `offline_policy` state-gates the online fallback. Re-run `skillctl install <skill>` to stash the metadata. Shares `25` with `translog`'s `translog_rewrite` under a different theme: the one tolerated legacy collision, both sides already shipped (see `TestCodes_KnownLegacyCollision25`). |
| `25` | `translog_rewrite` | `translog` | log rewrite | `translog consistency`: an append-only violation, the log was rewritten. |
| `26` | `local_audit_unavailable` | `enforce` | evidence / audit-durability | A `refusal_code`. `require_local_audit` is set and an allow could not be durably recorded, so the gate fails closed (SPEC-0317 R-8.2). |
| `27` | `sidechannel_denied` | `guard-path` | side-channel / path-guard | A `refusal_code`. The opt-in `guard-path` deny of a skill-directory side-channel access (SPEC-0317 R-6). |
| `28` | `offline_locked` | `state-machine` | offline / no-policy-basis | A `refusal_code`. The host is managed-enterprise with NO trust basis at all, so `offline_policy` denies every non-allowlisted managed skill. Restore a trust root or a signed offline checkpoint. |
| `29` | `ingest_rejected` | `sync` | egress / ingest | The ingest endpoint rejected the batch (auth or validation, a 4xx). Not retryable unchanged. |
| `40` | `audit_backend_config` | `sync` | egress / config | The audit-export backend selection was rejected (SPEC-0455): an endpoint is configured but no backend is named (set `SKILLCTL_AUDIT_BACKEND=er1`), the named backend is unknown, or its configuration is incomplete. |

<!-- exitaudit:register:end -->

### Codes outside the register

Not every exit number is a registered code, and the ones that are not have to be written
down anyway: `bundle_revoked` briefly claimed a `20` that `verify.ExitSelfAttested` had
been shipping for weeks, because the census had only ever been taken against the register.
Each row names the file that owns the number, and `cmd/exitaudit` fails if that file is
gone.

<!-- exitaudit:outside:begin -->

| Code | Surface | Source | Why it is not in the register |
|-----:|---------|--------|-------------------------------|
| `0` | all | `cmd/skillctl/signing_cmds.go` | Success. The register allocates failures; `0` is claimed by no code, and the invariant test skips it. |
| `1` | all | `cmd/skillctl/signing_cmds.go` | Generic error, deliberately unspecific. `pull` also returns it when bundles were skipped for DIFFERENT reasons: one number cannot describe two causes, and the per-bundle gate is on each row of the output. |
| `2` | all | `cmd/skillctl/signing_cmds.go` | Usage or flag error. Also the value a `PreToolUse` gate exits with to BLOCK a tool call (`exitHookBlock`), which is why gate refusals ride `refusal_code` instead. |
| `3` | `audit` | `pkg/skillctl/audit/audit.go` | The posture verdict "at least one skill is BROKEN" (SPEC-0189 §14.2). It cannot enter the register: `3` is held there by `pin`'s `need_priv_msg` under a different theme, and the number-theme invariant is what makes the register worth having. The two surfaces never run inside one command. |
| `6` | `import-public` | `(unimplemented)` | SPEC-0201 §11 assigns `6` to a bodyscan refuse. No such command exists in this tree, and `6` is now `pull`'s `bundle_revoked`. If `import-public` ever lands, it takes a free number. |
| `32` | `skillgate` | `pkg/skillgate/gate.go` | The runtime capability-envelope band `30`-`39` (SPEC-0202 §8.2) is a library constant band in the Python-reference gateway. **No `skillctl` subcommand emits it**; the Go-native OS-level cage is FR-0044, pending. It appears in the demo's ROADMAP scenario only. |

<!-- exitaudit:outside:end -->

`audit` uses its own scale: `0` all OK · `2` at least one `UNVERIFIED`/`BELOW_MIN` (or a
G-23 confirm-delete precondition refusal on drift) · `3` at least one `BROKEN`. `propose`
uses `0` pass / `2` gate failed. `auditlog` has its own `0/1` HEALTH verdict (SPEC-0403 §8),
which is why a health finding must never be read as a posture verdict; its `2` is the ordinary
usage code, not part of that verdict.

> Some commands print flags with a **single dash** in their own help output (e.g. `-key`,
> `-out`). Both `-<flag>` and `--<flag>` are accepted. This manual reproduces flag names as
> the command prints them, and shows examples in the common `--<flag>` form.
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

### `keygen`: generate an author keypair

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

Exit: `0` ok · `1` write / key-generation error · `2` usage.

---

### `pack`: build a `.skb` bundle

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
| `--author-intent green\|yellow\|red` | Advisory governance hint: **the verifier ignores it**; signed attestations bind. |
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

Exit: `0` ok · `1` pack error · `2` usage / validation error · `18` the declared intent contradicts `data_dependencies` (SPEC-0196 §3.3, the same number `intent declare` gives).

---

### `sign`: sign a bundle

```bash
skillctl sign --key PATH.priv [--identity-id ID] BUNDLE.skb
```

Computes the bundle's SHA-256 digest, signs the 32 raw digest bytes with ed25519, and writes
a **detached** signature: `<BUNDLE.skb>.<digest_hex>.author.sig` (64 raw bytes, mode `0644`).

| Flag | Purpose |
|------|---------|
| `-key` | Path to PEM PKCS#8 ed25519 private key (mode `0600`). **Required.** |
| `-identity-id` | Author identity id: **advisory only, NOT embedded in the signature**. The detached signature is over the bundle digest alone; author identity is bound at verify time via the trust-root pin (SPEC-0188 D4), not by this flag. Recorded for your own bookkeeping. |

```bash
skillctl sign --key ~/.config/m3c/skill-keys/mykey.priv my-skill.skb
```

Exit: `0` ok · `1` signing error · `2` usage.

---

### `verify-sig`: verify a detached signature (offline)

```bash
skillctl verify-sig --pubkey PATH.pub BUNDLE.skb
```

Recomputes the bundle's digest, locates the matching `.author.sig`, and verifies it. **No
network, no CA.**

| Flag | Purpose |
|------|---------|
| `-pubkey` | Path to PEM SPKI ed25519 public key. **Required.** |

```bash
skillctl verify-sig --pubkey ~/.config/m3c/skill-keys/mykey.pub my-skill.skb
```

Exit: `0` ok · `10` the bundle's bytes changed after signing (digest mismatch: checked BEFORE the signature, because an altered bundle is a digest failure first and the same `10` that `verify --bundle` gives for that cause) · `11` signature invalid · `1` other error · `2` usage.

---

### `trust`: manage trust roots

```bash
skillctl trust <list|add|remove> [flags]
```

Manages `~/.claude/skill-trust-roots.yaml` (SPEC-0188 §4.4): the registry keys you pin.
Multiple keys per registry are supported for rotation overlap windows. `rm` is an alias for
`remove`.

**`trust list`**: print configured registries and their pinned keys.

**`trust add`**: pin a registry public key.

| Flag | Purpose |
|------|---------|
| `-registry` | Registry URL (e.g. `https://aims.example.com/api/skills`). **Required.** |
| `-pubkey` | Path to PEM SPKI ed25519 public key file. **Required.** |
| `-id` | Optional key-id label (defaults to a short fingerprint-derived id). |

**`trust remove`**: unpin a registry (including all its keys).

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

### `peer`: pin a federated peer registry (SPEC-0359)

```bash
skillctl peer <add|ls|verify|rm> [args]
```

A peer is another registry you are willing to pull from. Pinning is **out-of-band only**:
`add` refuses unless `sha256(pubkey)` equals the `--pin` you supply, so there is no
trust-on-first-use window.

**`peer add <name> <locator>`**

| Flag | Purpose |
|------|---------|
| `--pubkey <b64>` | The peer's ed25519 signing key, base64. **Required.** |
| `--pin sha256:<hex>` | The peer's trust-root fingerprint, verified out-of-band. **Required**: `add` fails if it does not match `--pubkey`. |
| `--floor green\|yellow` | `governance_minimum` for this peer. |
| `--signer <reviewer-id>:<b64>` | A reviewer whose attestations count for this peer, as `id:alice@org:<pubkey_b64>` (repeatable). Omit it when the publisher and the reviewer are the **same** key: without any signer the registry key itself is the only acceptable attester (the D2 model). |
| `--quorum <n>` | How many **distinct** pinned signers must attest at or above the floor (default `1`). Refused unless at least that many `--signer` entries are given. |
| `--contributes-revokes` | Union this peer's **signed** revoke events into the local revoked set for `revoke feed --gossip`. Set it **only** for a governance-trusted peer: that is the bound that keeps a peer from mounting a revoke-DoS. |

**`peer ls`**, list pinned peers (name, locator, fingerprint, floor).
**`peer verify <name>`**, dry-run the §7 gauntlet against the peer's registry and pinned
key and report what would pass or fail. Installs nothing.
**`peer rm <name>`**: remove a pinned peer.

```bash
skillctl peer add alice https://alice.example.com/api/skills \
  --pubkey <base64> --pin sha256:<hex> --floor yellow
skillctl peer verify alice

# publisher and reviewer are DIFFERENT keys: pin the reviewer as a signer, or the
# pull refuses a perfectly valid attestation with
# "gate 4: no attestation at or above the trust-roots governance_minimum".
skillctl peer add kup github://kup/skill-registry \
  --pubkey <publisher-b64> --pin sha256:<hex> \
  --signer id:reviewer@kup:<reviewer-b64> --quorum 1
```

---

### `cross-sign`: a governance root vouching for a member reviewer (SPEC-0359)

```bash
skillctl cross-sign --member-id <id> --member-pubkey <b64> --not-after <when> [flags]
```

Issues a **governance-root-signed** statement that a member reviewer's key is recognised, so
an N-of-M attestation quorum can be satisfied by reviewers you did not pin one by one.

| Flag | Purpose |
|------|---------|
| `--key <path>` | **Governance root** private key (PEM PKCS#8 ed25519). **Required.** |
| `--member-id <id>` | Member reviewer identity id (e.g. `id:alice@org`). **Required.** |
| `--member-pubkey <b64>` | Member ed25519 public key, base64. **Required.** |
| `--not-after <when>` | Hard expiry: RFC3339, `YYYY-MM-DD`, or a duration like `8760h`. **Required**: a cross-signature with no end date is not one we will issue. |
| `--locator <url>` | Optional member registry locator. |
| `--out <file>` | Output file (default: stdout). |

```bash
skillctl cross-sign --key governance-root.priv \
  --member-id id:alice@org --member-pubkey <base64> --not-after 8760h --out alice.crosssig
```

---

### `install`: pull, verify, and install

```bash
skillctl install <name>[@<version>] [flags]
skillctl install --bundle <file.skb> [--meta <f>] [--trust-roots <f>] [--revocations <f>] [--checkpoint <f>] [--emergency <f>]
```

Pulls a bundle from the registry, runs the SPEC-0188 §7 verifier, and **atomically** installs
it under `~/.claude/skills/<name>/`. Refuses if *any* trust-chain step fails. `<version>` may
be a human version string (`1.0.0`) or a digest pin (`sha256:<hex>`); omit it to install the
newest admitted version.

`--bundle` installs a **standalone `.skb` file** that arrived over an untrusted transport
(SPEC-0406 D2): fully offline, against locally pinned trust-roots, with the sidecar
`<file>.skbmeta.json` (or `--meta`) as the envelope. It refuses for exactly the reasons
`verify --bundle` refuses, including the offline revocation inputs: a signed revocation
list (`--revocations`), a signed freshness checkpoint (`--checkpoint`) and a signed
emergency deny-list (`--emergency`) are enforced *before* anything is written, fail-closed
(an unreadable or forged list is an error, never a pass). Where the skill lands is decided
by the signed `bundle.json`, never by the file name. The three offline inputs require
`--bundle`; on the registry path they are refused rather than silently ignored.

| Flag | Purpose |
|------|---------|
| `-allow-yellow` | Lower the gate from green to yellow for this install (audited). |
| `-bundle` | Install a standalone `.skb` file from an untrusted transport, fully offline against pinned trust-roots (SPEC-0406 D2). |
| `-checkpoint` | Signed freshness checkpoint (SPEC-0279 R4) to reset the `--revocations` staleness clock (with `--bundle`). Forged/untrusted → `12`. |
| `-emergency` | Signed emergency deny-list (SPEC-0279 R5, with `--bundle`). Named digest → `17`; forged list → `12`. |
| `-governance-min green\|yellow` | Override the trust-root's `governance_minimum`. Empty = use trust-root. |
| `-home` | Override the install root (advanced; defaults to `$HOME`). |
| `-ignore-deps` | Skip `depends_on` resolution (audited). |
| `-meta` | Path to the BundleMeta envelope JSON for `--bundle` (default: the sidecar `.skbmeta.json`). |
| `-registry` | Registry base URL. Required only when trust-roots pins multiple registries. |
| `-revocations` | Signed revocation list to enforce offline (with `--bundle`), same semantics as on `verify --bundle`. Revoked digest → `17`; forged list → `12`; stale snapshot for a high-risk bundle → `22`. |
| `-tenant` | Pin this install to a tenant scope (§7 step 5.5). Overrides trust-roots `tenant_scope`. |
| `-timeout` | HTTP timeout for registry calls (default `30s`). |
| `-trust-roots` | Trust-roots YAML to use instead of the default. Pair with `--bundle` for a portable kit. |
| `-verbose` | Print structured per-step log lines to stderr. |

```bash
skillctl install my-skill@1.0.0
skillctl install my-skill@sha256:<hex> --verbose
skillctl install --bundle demo@1.0.0.skb --trust-roots roots.yaml --revocations revocations.json
```

Exit: `0`, `1`, `2`, plus every code `verify.ExitCode` maps out of the §7 chain that this path can actually raise: `10`–`17`, `20` (self-attested) and `22` (revocation snapshot stale). With `--bundle`, `17` also carries an emergency deny (see [Exit codes](#exit-codes)).

`23` (log inclusion missing) is NOT in that set, although `verify.ExitCode` maps it: the only function that raises `ErrLogInclusionMissing`, `verify.CheckLogInclusion`, has no caller outside its own test file, so no `install` or `verify` run reaches it. `23` is reachable today through `translog verify` alone.

---

### `verify`: re-run the trust chain

```bash
skillctl verify <name> [flags]
skillctl verify --all [--quarantine]
skillctl verify --bundle <file.skb> [--trust-roots <file>] [--json]
```

Re-runs the SPEC-0188 §7 trust-chain check against an already-installed skill: useful for
catching post-install revocations or trust-root rotations. `--all` re-verifies everything.

**Two carriers, one command** (FR-0116). A skill installed by `install` is anchored on the
HTTP trust-roots file; one installed by `pull --install` (self/ER1 or a git registry) is
anchored on `~/.claude/trust-roots.yaml` or on a peer pinned with `peer add`, and carries
`.m3c-provenance.json` + `.skillctl-attest.json` to prove it. `verify <name>` tries the HTTP
model first and falls back to that sidecar tier, resolving the peer whose locator matches the
registry recorded in the provenance. A missing `skill-trust-roots.yaml` is therefore no longer
the end of the command: it is the end of only one of the two paths.
`--bundle` verifies a **standalone `.skb` file** with no install state and no network, against
locally pinned trust-roots: the trustless third-party path (requires a `<file>.skbmeta.json`
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

**`verify --all`: the fleet sweep** (SPEC-0247 P0.2). `--all` is detected *before* flag
parsing and switches to a different flag set, because the sweep is a different job: verify
every installed skill, report one verdict per skill, and optionally quarantine the failures.

| Flag | Purpose |
|------|---------|
| `--all` | Run the sweep over every installed skill instead of verifying one by name (`-all` also works). |
| `--quarantine` | Move TRUST-failing *managed* skills out of `~/.claude/skills/` into the quarantine dir. |
| `--budget` | Total wall-clock budget for the sweep. Skills not reached are reported `unverified`, never quarantined, so a slow registry cannot delete your skills. |
| `--session-id` | Stamp the recorded verdict-cache rows with this session id (the one from the `SessionStart` event). |

```bash
skillctl verify my-skill
skillctl verify --all
skillctl verify --bundle my-skill.skb --trust-roots ./roots.yaml --json
```

Exit: same as `install` (see [Exit codes](#exit-codes)).

---

### `attest`: post a governance attestation

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

### `revoke`: revoke an admitted bundle (and the kill-switch feed)

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
| `-role registry_operator\|governance_reviewer\|original_author` | Name the actor role explicitly instead of inferring it from `--actor-identity`. |
| `-key` | Signing key for the revocation event. Required for the `original_author` (default) and `governance_reviewer` roles. |
| `-registry` | Registry base URL. |
| `-timeout` | HTTP request timeout. |

Three actor roles: **`original_author`** (the default: signs with the author key),
**`governance_reviewer`** (`--actor-identity` + `--key`), and **`registry_operator`**
(unsigned, operator-authenticated).

```bash
skillctl revoke sha256:<hex> --reason key_compromise --registry https://aims.example.com/api/skills
```

**`revoke feed`, the fleet kill-switch feed (FR-0045 D5).** A distinct, operator-facing mode:
it views or refreshes the signed **revocation HEAD**, a HEAD-aware, signed snapshot of the
current revocation set that the verifier fetches and enforces fail-closed. `feed` is
intercepted as the first argument **before** any digest parsing, so it is never mistaken for a
bundle digest.

| Flag | Purpose |
|------|---------|
| `-status` | **(default)** Fetch the signed revocation HEAD, verify it against the pinned registry key, and print its epoch / issued-at / staleness / counts. Read-only; does **not** adopt it into the local cache. |
| `-refresh` | Run the revocation sweep now: fetch the latest signed HEAD **and adopt it** into the local cache + freshness anchor the gate reads. |
| `-registry` | Registry base URL. |
| `-tenant` | Scope the feed to a tenant. |
| `-gossip` | Union the **signed** revoke events of pinned peers that were added with `peer add --contributes-revokes` into the durable local revoked set (SPEC-0359 D5(b)). Only signed events count, and only from peers you marked as contributing, that bound is what stops a peer from mounting a revoke-DoS. |

Because the HEAD is signed and checked against a **pinned** registry key, a MITM'd, mirrored,
truncated, rolled-back, replayed, or forged feed is rejected rather than trusted. This is the
transport-side, fail-closed kill-switch. It is **not** tamper-evident against a same-UID
compromised local process. Live fleet propagation of the HEAD is still rolling out; the offline
enforcement contract (a revoked digest → `17`, a stale snapshot → `22`) is built and testable
today.

```bash
skillctl revoke feed --status
skillctl revoke feed --refresh --registry https://aims.example.com/api/skills
```

Exit: `0` the revocation was accepted · `1` generic / network / an HTTP 403 refusal · `2`
usage, a bad flag, or an HTTP 400 from the registry · `15` the registry answered HTTP 404
(this digest was never admitted) or HTTP 409 (it is already revoked) · `22` `revoke feed
--refresh` could not obtain the revoked set on a managed host and failed closed.

The `15` is the number only, not the theme: the register holds it under
`verify`/`blob_missing`, so branch on it per verb and never read it as a chain failure.
Measured at the binary against a local registry stub, and against
`cmd/skillctl/revoke_cmds.go`.

`revoke feed --refresh` adds one more: `22` when the host is MANAGED (a `trust-roots.yaml` is
present) and the revoked-set fetch is unavailable with no authenticated grace cache. That is
deliberately the same `revocation_stale` number the hook and the `verify --all` sweep use
(`cmd/skillctl/revoke_feed_cmds.go`), so one script branch catches the fail-closed signal at all
three sites. Measured at the binary with a present but unloadable `~/.claude/trust-roots.yaml`.

Related paths: `publish --revoke` posts the same `BundleRevokedEvent` to your personal ER1
`self` registry (see [`publish`](#publish--admit--attest--revoke-via-er1-self-registry)), and
`agentid revoke` adds `agent:<id>` to a signed AgentID revocation list. All three produce
signed, offline-verifiable lists the verifier honours fail-closed.

---

### `audit`: antivirus-style verdict per skill

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
disappeared, or changed), or the token expired or was tampered, the confirm **refuses** and
exits `2` (a usage / precondition refusal), deleting nothing. Both the plan and the refusal
are auditable, and there is **no `--force`** to bypass the re-check: a destructive op that no
longer matches its approved plan simply does not run.

Exit: `0` all OK · `1` an internal failure (the inventory scan failed, the cleanup token could
not be built, or a `--confirm-delete` deleted only part of its plan) · `2` ≥1
`UNVERIFIED`/`BELOW_MIN`, **or** a confirm-delete precondition refusal (drift/expiry/tamper),
**or** a usage / flag error · `3` ≥1 `BROKEN`.

Only `0/2/3` are the POSTURE verdict (`exitCodeFor`, `pkg/skillctl/audit/audit.go`); `1` is the
ordinary internal-error code every verb has, measured at the binary with a confirm-delete into a
read-only skills directory.

---

### `envreport`: skill-env report for one regulated environment

```bash
skillctl envreport --mandant <id> --prinzipal <id> --einwilligung-art <selbst|eingesetzt> \
                   --einwilligung-beleg <text> --aufbewahrung-tage <n> [flags]
```

Collects what `audit` sees into a **skill-env report** (SPEC-0428): one immutable,
dated statement of what a single environment held at one moment. The body is the
SPEC-0351 §5.1 `posture.snapshot` payload, verbatim.

**A dry run is the default.** Without `-schreiben` nothing is stored. The usual
default is the other way round; it is wrong here, because a slip creates personal
data and not merely a file. The report boundaries (hashed host, no source text
off-box, consent, retention deadline) run in the dry run too: a dry run that knows
different rules than the real thing proves nothing about the real thing.

| Flag | Purpose |
|------|---------|
| `-mandant <id>` | Tenant of the environment. Required; salts the host hash. |
| `-prinzipal <id>` | The person whose environment this is. Required. |
| `-einwilligung-art selbst\|eingesetzt` | Consent kind. Required: whoever is observed must know. |
| `-einwilligung-beleg <text>` | What the consent or notification hangs on. Required; consent without evidence is not consent. |
| `-aufbewahrung-tage <n>` | Retention in days. Required, no default: a statement about a person's working behaviour that never expires is not retention. |
| `-source claude\|user\|plugins\|all` | Collection scope (default: all). |
| `-json` | Report as JSON instead of a table. |
| `-schreiben` | Store the report. Without it: dry run. |
| `-er1-target prod\|stage\|local` | Which ER1 to write to (default: prod). Only read with `-schreiben`. |
| `-er1-context <id>` | ER1 context (default: `<owner-sub>___skillenv`). The owner is the authenticated user, NOT the tenant of the env address: `_owner(ctx_id)` in aims-core is everything before `___` and is checked against the principal. Only read with `-schreiben`. |

The host never appears in clear text: the environment address carries a salted
hash, and there is deliberately no function that resolves it back.

With `-schreiben` the report is stored as an ER1 item carrying the eight marks of
SPEC-0428 E3, hung off the environment's anchor item via `link/parent`. The store
is **append-only**: an already-used `(env, seq)` is refused, never overwritten.
After the write the verb **reads the report back** and fails if it cannot find it,
because a write that only claims to have written is the expensive failure in this
class.

### `trust-freeze`: record, approve and compare a host's state (SPEC-0466)

```bash
skillctl trust-freeze doctor [--profile <name>] [--output <dir>] [--format text|json]
skillctl trust-freeze capture --profile <name> --output <dir> [--actor <id>] [flags]
skillctl trust-freeze baseline approve --capture <dir> --output <dir> --reviewer <id> \
                                       --change-id <id> --reason <text|@file> --key <file> [flags]
skillctl trust-freeze verify --bundle <dir> [--trust-policy <file>] [--trusted-key <public.pem>]...
skillctl trust-freeze diff --baseline <dir> --current <dir> [flags]
skillctl trust-freeze report --input <dir> --output <file|dir> [--format json]
```

Trust Freeze records what a host looks like as a **capture** bundle, lets a person
approve one capture as a signed **baseline**, verifies bundles offline, and compares a
later capture against the baseline as a **diff**. The owning specifications are
SPEC-0466 to SPEC-0471. It is distinct from `drift`, `envreport` and `audit`, which
keep their meaning.

It is read-only toward the host: no sudo, no elevation prompt, no install, no service
start, no configuration change, no network. Its only write is the output directory you
name. A capture is never a baseline, and no command turns one into the other except
`baseline approve`: there is no automatic baseline update, a changed state always needs a
new explicit approval, and `capture` never calls the approval code.

**What this version collects.** `common.identity` runs on every platform: the artifact
`device/os` (`os_family`, `arch`, `os_name`, `os_version`, `os_build`, `kernel_release`)
and `device/host` (`hostname`, sensitivity `internal`). `arch` is the machine as the OS
reports it, spelled like Go's `GOARCH` (`amd64`, `arm64`, ...), never the architecture
skillctl was built for: an `amd64` build under Rosetta 2 or under Windows x64 emulation
records `arm64`. The profile `walking-skeleton` requires only that probe.

Nine more probes collect a Linux host. They are registered on every platform and
recorded as `unsupported` with the platform as the reason where they cannot run, so a
capture never hides them:

| Probe | Reads | Honest outcomes besides `captured` |
|-------|-------|------------------------------------|
| `linux.packages` | `dpkg-query -W -f`, `apt-mark showmanual`, `snap list` | `unavailable` without `dpkg-query`; the snap inventory is `unavailable` with the searched directories named when `snap` does not resolve, never an empty snap list |
| `linux.users` | `getent passwd`, `getent group`, `id` | `unavailable` without `getent`. Never a password hash: `getent` prints none and nothing else is read. When `getent passwd` printed accounts and no artifact of the inventory is uid 0, an `account_root_missing` diagnostic names the gap and the probe is `partial`: a missing root account is stated, never left to be found by counting the rest |
| `linux.sudo` | `/etc/sudoers`, `/etc/sudoers.d` (file names, modes, owners, sizes, parsed rules) | `permission_denied` for every file an ordinary user cannot read, with the observed structure still recorded |
| `linux.ssh` | `/etc/ssh/sshd_config` and `sshd_config.d/*.conf` (declared), `sshd -T` (effective), `getent passwd` plus `authorized_keys` per account | `permission_denied` for the effective state without root; `partial` where one source is missing and the rest was read (a host without `sshd` keeps its declared state and is partial, not `unavailable`); the declared state stays `declared` and is never presented as observed |
| `linux.systemd` | `systemctl list-unit-files`, `systemctl show` | `unavailable` without `systemctl`. Enabled state and active state are two different facts and are recorded as two artifacts. A TEMPLATE unit (`getty@.service`, an empty instance part) is never asked about: it has no instance and therefore no runtime state, so its unit artifact carries `template=true` and `runtime_state=not_applicable` with the reason, and the manager artifact counts them in `template_unit_count`. When a `systemctl show` call for several units stops before answering for all of them, the blocks that arrived are kept and the remaining names are asked for one at a time, so one name the manager refuses costs one unit and not a batch; a `show_batch_split` diagnostic says how many were re-queried and a `unit_state_not_read` diagnostic names each unit that stayed unknown |
| `linux.mounts` | `findmnt --json` | `unavailable` without `findmnt` |
| `linux.network.listeners` | `ss -H -lntup` | `partial` unprivileged: the owning process of a foreign socket is not visible, and the diagnostic says so |
| `linux.firewall` | `nft --json list ruleset`, else `ufw status` | `permission_denied` when a backend is installed and refuses without root; `unavailable` when neither tool is found, with the searched directories named. Not `not_applicable`: a host filters packets with backends this build does not read |
| `linux.containers` | `docker ps`, `docker info`, the same for podman | `unavailable` when neither client is found, with the searched directories named; `permission_denied` when the daemon socket refuses, carrying what the client printed; `failed` when the daemon is unreachable. The runtime artifact records the resolved path (`/snap/bin/docker` for a snap) and the client version of that path |

The profile `ubuntu-bastion` requires `common.identity` and the eight Linux probes above
except `linux.containers`, which is optional. It still lists `common.git` and
`common.claude`, which this version does not implement: they are recorded as
`unsupported` with reason `not_implemented`, so an `ubuntu-bastion` capture is
`incomplete` (exit `1`) even on a Linux host. On an unprivileged host `linux.firewall`
is `permission_denied` as well, which is the correct answer and keeps the capture
incomplete; a complete `ubuntu-bastion` capture needs a run with the privileges those
probes name. A host with neither `nft` nor `ufw` keeps the capture incomplete too,
because `linux.firewall` is then `unavailable` and not a statement that the host has no
firewall. The profiles `agentic-workstation`, `windows-wsl-workstation` and
`macos-workstation` list probes that are not implemented at all, so those captures are
`incomplete` as well.

**Evidence level per platform** (this change):

| Probe | Platform | Source | Evidence level |
|-------|----------|--------|----------------|
| `common.identity` | linux | `/etc/os-release` (else `/usr/lib/os-release`), `uname -r`, `uname -m` | implemented, fixture-tested, cross-compiled |
| `common.identity` | darwin | `sw_vers`, `uname -r`, `uname -m`, and `sysctl -n sysctl.proc_translated` when `uname -m` says `x86_64` | implemented, fixture-tested, cross-compiled |
| `common.identity` | windows | registry `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`; the native machine from `IsWow64Process2` | implemented, fixture-tested, cross-compiled |
| the nine `linux.*` probes | linux | the tools named in the table above | implemented, fixture-tested, cross-compiled |
| the nine `linux.*` probes | darwin, windows | n/a | not implemented; recorded as `unsupported` with the platform as the reason |

No platform is real-platform-tested in this change. That level is recorded per commit in
evidence records, never claimed by the build, and full platform support is not
established. `doctor` prints the same matrix from the code.

**The lifecycle, end to end:**

```bash
mkdir -p ./keys ./tf
skillctl keygen --out ./keys/reviewer                    # reviewer.priv (0600), reviewer.pub
skillctl trust-freeze capture --profile walking-skeleton --output ./tf/capture-1
skillctl trust-freeze baseline approve --capture ./tf/capture-1 --output ./tf/baseline-1 \
    --reviewer alice --change-id CHG-0001 --reason @./reason.txt --key ./keys/reviewer.priv
skillctl trust-freeze verify --bundle ./tf/baseline-1 --trusted-key ./keys/reviewer.pub
skillctl trust-freeze capture --profile walking-skeleton --output ./tf/capture-2
skillctl trust-freeze diff --baseline ./tf/baseline-1 --current ./tf/capture-2 \
    --trusted-key ./keys/reviewer.pub --output ./tf/diff-1
skillctl trust-freeze report --input ./tf/diff-1 --output ./tf/report-1.json
```

`scripts/trustfreeze-acceptance.sh` runs this path against a freshly built binary in a
temporary directory with a throwaway key.

**Privacy: bundles, diffs and reports are internal host data.** A capture or baseline,
and the report of one, carries the host name in clear text (`device/host`, sensitivity
`internal`) and the OS details. A Linux capture carries considerably more, all of it in
clear text and all of it inside the content digest:

- every local account with its name, uid, gid, login shell and home path (`device/user/*`),
  and every group with its gid and its member list (`device/group/*`);
- `capture.actor`, which is whatever the operator passed to `--actor` and may be a mail
  address;
- for every `authorized_keys` file this capture could read: the account it belongs to and,
  per key, the key type, the SHA-256 fingerprint and the names of its options
  (`ssh/authorized-key/*`). Never the key body and never its comment;
- the principals of every sudo rule (`sudo/rule/*.users`), the rule's commands and tags,
  and the mode, owner and size of every rule file;
- every listening address and port with the owning process name where it was visible
  (`network/listener/*`), every mount point and source, every container name, image and
  published port, and the installed package and unit inventory;
- the resolved capabilities, which name accounts and groups by name
  (`state/capabilities.json`).

A diff, and the report of a diff, carries no attribute values, but it is not anonymous
either:

- `before_digest` and `after_digest` are plain SHA-256 over the canonical JSON of the
  normalized attribute map, without a key or salt. A short value such as a host name
  or an OS version can be recovered by hashing a dictionary of candidates.
- The subject id (`device/` plus 16 hex characters of a SHA-256 over the OS family and
  the lower-cased host name) is a pseudonym, not an anonymization: whoever knows or
  guesses the host name recomputes it. Bundle ids contain it as well.

Keep bundles, diffs and reports inside the trust boundary they were made in and do not
share them outside it. A keyed digest (HMAC) that would keep these values unlinkable
outside that boundary is future work; this version does not have one.

**Result classes.** The exit space is the shared base space and allocates no new number.
Exit `1` has several causes; the JSON output of every subcommand names the cause in
`result_class`:

| `result_class` | Exit | Meaning |
|----------------|------|---------|
| `ok` | `0` | The command did what it was asked. For `diff`: the threshold was not reached. |
| `usage_error` | `2` | A flag is missing, malformed or names an option this version does not implement. One rule covers every input file a flag names (`--key`, `--trusted-key`, `--trust-policy`, `--policy`, `--reason @file`): a file that fails to load (missing, unreadable, malformed, a key file with a mode more open than `0600`) is a `usage_error`, never an `execution_error`. |
| `execution_error` | `1` | The run failed: unusable output target, a home root that cannot be resolved, write error. |
| `verification_failure` | `1` | A bundle failed its check, or a blocked self-approval refused the approval. |
| `drift_threshold_exceeded` | `1` | `diff`: the highest finding severity is at or above `fail_on`. |
| `incomplete_capture` | `1` | `capture`: the bundle was written, but a required probe has a gap. |

Exit: `0` ok · `1` a run that failed (`execution_error`, `verification_failure`,
`drift_threshold_exceeded`, `incomplete_capture`) · `2` usage or flag error, including an
option that answers "not implemented in this version". Measured against
`runTrustFreeze` in `cmd/skillctl/trustfreeze_cmds.go` by its tests.

#### `trust-freeze doctor`: what a capture could collect here

Runs only the support check of every probe of a profile and prints the platform, the
privilege, the expected gaps, the per-platform evidence matrix and the environment
checks. Writes no bundle and captures nothing.

| Flag | Purpose |
|------|---------|
| `--profile <name>` | Built-in profile to plan (default `walking-skeleton`). |
| `--output <dir>` | Bundle directory a later capture would use (optional). doctor only tests whether it could write there; it writes no bundle and creates no directory. It touches one directory: the target itself when that already exists, otherwise its immediate parent. |
| `--format text\|json` | Output format (default `text`). |

The JSON carries `platform_support: "not_established"` and the matrix with `implemented`
or `not_implemented` per probe and platform.

**Environment checks** (`checks` in the JSON, one entry per item, `status` one of `ok`,
`problem`, `not_checked`):

| Item | What doctor does |
|------|------------------|
| `claude_roots` | Resolves the home root the way every other skillctl path does, then `lstat`s `.claude`, `.claude/agents`, `.claude/commands`, `.claude/skills`, `.claude/skillctl` and `.claude/trust-roots.yaml` below it. It opens no file, follows no link and creates nothing. `detail` names the root and lists which paths are present and which are absent. A path that exists as a symlink, or that cannot be read, is a `problem`. |
| `output_location` | Only with `--output`. Picks the directory a capture would work in, creates ONE temporary file there, closes it and removes it again, and touches nothing else. That directory is the target itself when it already exists as a directory, otherwise its IMMEDIATE parent, because capture creates the target inside its parent and creates no directory above it. doctor never walks further up: `--output /srv/freeze/2026-09-23` touches `/srv/freeze` when that exists, and when it does not the item is a `problem` naming it, never a probe file in `/`. Permission bits are not read instead: a read-only mount, an ACL, a container user mapping or Windows can each make them disagree with what a write would do. Without `--output` the item stays `not_checked`. |
| `tools` | Resolves every executable a probe names for itself, through the same fixed search path the command runner uses, and runs none of them. `detail` names each resolved tool as `<probe-id>:<tool>` and each one that did not resolve with its class (`tool_missing`, `permission_denied`). A probe that names no executable cannot be checked this way; when no probe of the profile names one, the item stays `not_checked` with that reason. Per-probe rows carry the same result under `tools`. |

`not_checked` repeats every item doctor could not determine, each with its reason, so a
reader sees the gaps without filtering `checks`.

Exit: `0` plan printed, also when gaps are expected and also when a check reports
`problem` (see `expected_complete` and `expected_gaps`; doctor reports, it does not
judge) · `1` the probe registry could not be built (`execution_error`) · `2` usage,
including an unknown profile.

#### `trust-freeze capture`: write a capture bundle

| Flag | Purpose |
|------|---------|
| `--profile <name>` | Built-in profile (required). |
| `--output <dir>` | New bundle directory (required). Must not exist, or be empty, and must not lie inside an existing trust-freeze bundle. |
| `--actor <id>` | Stable id of the person or automation running this capture (optional). Recorded as `capture.actor` and carried into the signed approval as `identities.capture_actor`, where it is the reviewer's counterpart in the same-person half of the self-approval check. Same character set as `--reviewer` (see Identifiers below); surrounding white space is trimmed, anything else is refused with exit `2` before anything is written. Without it the capture names no actor and the same-person check has nothing to compare, exactly as before. |
| `--force` | Replace an existing **capture** bundle at `--output`, and only one that verifies (every file manifested and intact), so no file of yours is ever removed. Never a baseline, never the home root or one of its ancestors, a filesystem or volume root, or a mount point. |
| `--probe <id>` | Run only this probe of the profile (repeatable). Every other probe of the profile is recorded as skipped (see below). |
| `--exclude-probe <id>` | Skip this probe (repeatable). A skipped probe is recorded, not left out (see below). |
| `--timeout <d>` | Timeout per probe run, e.g. `30s` (default: the probe's own). |
| `--project <path>` | Not implemented in this version (exit `2`). |
| `--policy <file>` | Not implemented in this version (exit `2`). |
| `--format text\|json` | Output format (default `text`). Prints the manifest `content_digest`. |

The bundle is written to a staging directory next to the target, verified, and renamed
into place. A probe failure never aborts the capture; it is recorded with one of the
statuses `captured`, `partial`, `unsupported`, `unavailable`, `permission_denied`,
`timeout`, `failed` or `not_applicable`, and completeness is computed from them.

A probe that `--probe` or `--exclude-probe` leaves out is still recorded, as
`unsupported` with reason `excluded_by_operator`, so the bundle names every probe of its
profile: a skipped required probe makes the capture incomplete, and `diff` reports every
skipped probe as a `collection_gap` that the policy judges like any other gap.

Layout: `manifest.json`, `capture.json`, `state/device.json`, `probes/<probe-id>.json`,
`evidence/<probe-id>/<name>` (raw evidence, redacted before it is written), and on a
platform with a capability resolver `state/capabilities.json`.

**Capabilities.** After the probes have run, the capability resolver of the platform
turns their artifacts into statements about who may do what: a sudo rule that grants
every command as root, membership in a group that grants sudo (`sudo`, `admin`, `wheel`),
membership in a group that reaches a container runtime socket (`docker`, `lxd`), an
authorized key for an account, and a container the runtime reports as privileged. The
subject of that last one is the CONTAINER, not a principal: a privileged container keeps
the host device nodes and may mount and write the host filesystem, so what runs in it
acts as root with nobody logged in. Its state is `declared` (the runtime reports the
flag, nobody watched the container reach the host), its privilege is
`root-via-privileged-container`, and its source is the container artifact. A container
whose privileged flag was never read, because the `inspect` call did not answer, yields
no capability in either direction. Each capability names the artifacts it rests on, its
privilege, and, where the privilege needs an explanation, attributes that give it: a
`docker` group capability carries `grant_path: container-runtime-socket` and a
`rationale` saying that a container started through that socket can mount the host
filesystem and write as root, which is why its privilege is `root-via-container-runtime`
and not a sudo value. A statement the artifacts do not carry is a diagnostic, never
silence: an unreadable sudo file or `authorized_keys` file yields
`privilege_source_unreadable`, a group whose membership nobody collected yields
`group_membership_unknown`, a runtime group membership yields
`capability_from_runtime_group` with the runtime this capture did or did not observe (one
diagnostic per capability, also when the same account is visible both in the group
artifact and in its own group list), and a privileged container yields
`capability_from_privileged_container`, which also says that who may start or enter that
container is not answered by the artifacts of this capture. The
document names the resolver that produced it. Linux has one (`linux.privilege/v1`); darwin and windows have
none in this version, and a bundle without `state/capabilities.json` therefore says that
nobody resolved capabilities, never that the host grants nothing. The resolver sees only
what the probes recorded: where `linux.sudo` was `permission_denied`, the privileges in
that file are not in the document, and the collection gap in `capture.json` is what says
so. The text output prints the count, the resolver and the number of capabilities that grant
root, and then one line per such capability with its id and its privilege, so the reader
of a capture sees who holds the host without opening `state/capabilities.json`. The JSON
output carries `capabilities` with `resolver`, `resolved`, `diagnostics` and `critical`,
the sorted ids of the same capabilities. A capability counts as granting root when its
privilege is `root`, `root-via-container-runtime`, `root-via-privileged-container`,
`root-via-sudo` or `root-via-sudo-nopasswd`. That is a projection of what the resolver
wrote, not a judgement: severities belong to a policy, and a policy judges a diff.

Exit: `0` complete · `1` written but incomplete (`incomplete_capture`), or not written
(`execution_error`) · `2` usage.

#### `trust-freeze baseline approve`: approve a capture as a signed baseline

| Flag | Purpose |
|------|---------|
| `--capture <dir>` | Capture bundle to approve (required). Only read; it must verify. |
| `--output <dir>` | New baseline directory (required). Must not exist or be empty, and must lie outside the capture and any other trust-freeze bundle; a baseline is never overwritten. |
| `--reviewer <id>` | Reviewer id (required): an identifier, see below. |
| `--change-id <id>` | Change or ticket id (required): an identifier, see below. |
| `--reason <text\|@file>` | Why this state is accepted (required). `@file` reads the text from a file; CRLF becomes LF, so the signed bytes do not depend on the editor. A file that is the `--key` file is refused before it is read. |
| `--key <file>` | ed25519 private key, PEM PKCS#8, mode `0600` (required), e.g. from `skillctl keygen`. A key file that does not load (missing, not such a key, mode more open than `0600`) is a usage error. |
| `--expires-at <rfc3339>` | Optional expiry in any offset, stored in UTC. The baseline is valid through this instant, inclusive. |
| `--self-approval allow\|warn\|block` | What a self-approval does (default `warn`). |
| `--format text\|json` | Output format (default `text`). |

The mandatory fields are checked before the capture or the key is read, and long before
anything is signed.

**Identifiers.** The reviewer id and the change id are 1 to 128 characters of ASCII
letters, digits and `.` `_` `-` `@` `+` `:`, after surrounding white space is trimmed
(`alice@example.com`, `CHG-0001`). White space inside, a slash, a non-ASCII look-alike
or anything longer is refused with exit `2` before anything is read or signed, so an id
enters the signed approval the same way on every platform. verify applies the same rule
to `reviewer`, `change_id`, `identities.reviewer_id` and `identities.capture_actor` and
fails an approval that breaks it as `approval_invalid`.

Approval text is signed, so it can never be redacted afterwards: a
reviewer, change id, reason or policy reference that the redaction patterns flag as secret
material (a private key block, a bearer or authorization value, a token, a key and value
pair such as `password=...` or `?token=...`) is refused with exit `2`, naming the field and
the pattern class but never the text. The capture is copied byte for byte into the new directory and never
modified; `approval.json` is added, a new `manifest.json` (kind `baseline`) is written, and
then `signatures/manifest.ed25519.json`.

**Self-approval.** The approval records the captured subject, the capture actor (when the
capture has one), the reviewer, the signing key id and the approving device. The approving
device's subject id is derived from its OS family and host name exactly as the captured
subject is. `warn` reports `self_approval_same_device` (approving on the captured machine)
or `self_approval_same_person` (reviewer equals capture actor); `block` refuses the
approval. When the approving device is unknown (its host name could not be read), the
same-device check cannot run: `warn` reports `self_approval_device_unknown`, and `block`
refuses, at approval and at verification, instead of passing a check it could not
evaluate. The same-person check compares `identities.capture_actor` with the reviewer
after trimming and without regard to letter case; a capture taken without
`capture --actor` records no actor, and then that half has nothing to compare.

**Signature.** The signed message is the domain line `m3c-tools/trust-freeze/baseline/v1`,
a newline, and the canonical JSON of the statement `{domain, schema_version:
"trust-freeze/baseline/v1", kind: "baseline", capture_content_digest,
baseline_content_digest, approval}`. `key_id` is `ed25519:` plus the first 16 hex characters
of the SHA-256 of the raw public key. `statement_sha256` is the SHA-256 of the signed
message; verify rebuilds the statement from the files on disk and never trusts that value
alone. No private key material is written anywhere.

Exit: `0` baseline written · `1` the capture failed its checks (also a baseline or diff
given as `--capture`, or a capture whose documents contradict each other) or the
self-approval was blocked (`verification_failure`), or not written (`execution_error`) ·
`2` usage, including a missing or malformed reviewer or change id, a missing reason,
approval text that looks like secret material, or a `--key` or `--reason @file` that
does not load.

#### `trust-freeze verify`: check a bundle offline

| Flag | Purpose |
|------|---------|
| `--bundle <dir>` | Bundle to verify (required): a baseline, a capture or a diff. |
| `--trust-policy <file>` | Trust policy file (JSON or YAML). |
| `--trusted-key <public.pem>` | ed25519 public key (PEM SPKI, e.g. a `keygen` `.pub`) to trust (repeatable). |
| `--format text\|json` | Output format (default `text`). |

A **baseline** is checked completely (`scope: "baseline"`): manifest, every size and
digest, unexpected files, the kind layout (nothing under `signatures/` but the one,
unlisted signature file), `capture.json`, `approval.json` and its mandatory fields, the
capture digest, the signature over the rebuilt statement, key trust, expiry, the approval
time and the self-approval mode. For a
capture and for the capture inside a baseline, `capture.json`, every
`probes/<probe-id>.json` and `state/device.json` must agree (the probe list, each status
and reason, completeness recomputed from the probe results, the device state, every
evidence reference); a contradiction fails as `capture_invalid`. A valid signature by a key that is not trusted fails as
`key_not_trusted` and still reports `signature_valid: true`. Without trust material every
baseline fails that way. A **capture** or **diff** carries no signature; its check
(`scope: "integrity"`) is the manifest plus a strict parse of its documents.

**Capture digest.** `approval.json` names the approved capture by `capture_digest`. verify
does not take that value on trust: it rebuilds the capture manifest from the baseline
itself (kind `capture`, `created_at` = `finished_at` of `capture.json`, the bundle id
derived from that time and the subject, the baseline's subject, `reject_additions: true`,
and the baseline's files without `approval.json`) and fails with
`capture_digest_mismatch` when the content digest of that manifest differs. `capture`
writes exactly this manifest, so a baseline approved from an untouched capture matches.
`baseline approve` does not check the rule yet: a capture whose manifest follows another
rule (one that `capture` did not write) is approved, and its baseline then fails verify
with `capture_digest_mismatch`.

**Time.** Expiry and approval time are checked against the verifier's clock, and each
has a tolerance of its own, because the two are different statements.

`max_clock_skew` (default `5m`, `0s` disables it) is the approval tolerance: an
`approved_at` more than that after now fails as `approved_in_future`, because an approval
cannot have happened later than the moment it is checked. The tolerance exists because
two machines whose clocks differ by seconds are the normal case, and a signer whose clock
runs ahead is an accident that should not turn a sound baseline into a verification
failure; five minutes is far below any sensible baseline lifetime.

`max_expiry_skew` (default `0s`) is the expiry tolerance: an `expires_at` more than that
before now fails as `expired`, so with the default an expired baseline is expired to the
nanosecond. It is a separate setting, and its default is zero, because an expiry is not an
accident: it is a promise the approver made to the verifier, and stretching it would
extend a validity somebody decided on. An operator who wants the expiry to absorb clock
drift as well sets `max_expiry_skew` explicitly, and the trust policy then says so.

A policy that names neither field gets both defaults. A negative value in either is
refused.

Failure reasons: `integrity` (with `integrity_reason`: `missing`, `extra`,
`size_mismatch`, `digest_mismatch`, `duplicate_path`, `bad_path`, `symlink`,
`content_digest_mismatch`, `unknown_kind`, `unknown_schema`, `kind_layout_violation`,
`manifest_invalid`, `not_regular`, `unreadable`), `wrong_kind`, `missing_approval`,
`missing_signature`, `capture_invalid`, `approval_invalid`, `signature_malformed`,
`domain_mismatch`, `signing_key_mismatch`, `statement_mismatch`, `bad_signature`,
`key_not_trusted`, `capture_digest_mismatch`, `expired`, `approved_in_future`,
`self_approval_blocked`, `trust_policy_invalid`, `canceled`, and for a diff bundle
`diff_invalid`.

Trust policy file (schema `trust-freeze/trust-policy/v1`):

```yaml
schema_version: trust-freeze/trust-policy/v1
self_approval: warn                  # allow | warn | block
reject_additions: true               # false is not implemented in this version
max_clock_skew: 5m                   # approved_at; Go duration, default 5m, 0s disables
max_expiry_skew: 0s                  # expires_at; Go duration, default 0s
trusted_keys:
  - key_id: ed25519:0123456789abcdef # optional; checked against the key when present
    public_key: <base64 of the raw 32-byte ed25519 public key>
```

A JSON trust policy is read as strictly as a YAML one: a duplicate key, or a key that
differs from a field name only in letter case, is refused.

Exit: `0` PASS · `1` FAIL (`verification_failure`) · `2` usage, including a trust
policy or key file that does not load.

#### `trust-freeze diff`: compare a verified baseline with a current bundle

| Flag | Purpose |
|------|---------|
| `--baseline <dir>` | Baseline bundle (required). |
| `--current <dir>` | Current bundle (required): a capture or a baseline. |
| `--trust-policy <file>` | Trust policy for verifying the inputs. |
| `--trusted-key <public.pem>` | Trusted key for verifying the inputs (repeatable). |
| `--policy <file\|id>` | Policy file (JSON or YAML, schema `trust-freeze/policy/v1`), or the id of a built-in policy: `trust-freeze/policy/default-v0`, `trust-freeze/policy/default-v1`. Default `trust-freeze/policy/default-v1`. |
| `--fail-on none\|low\|medium\|high\|critical` | Threshold for exit `1` (default: the policy's `fail_on`, `high` for default-v1). It changes only the exit code and `threshold_exceeded`. |
| `--allow-subject-mismatch` | Compare two different devices on purpose, for a golden-image or fleet baseline. The `subject_changed` finding stays in the diff and is rated as allowed (`info` under default-v1), and the diff records the opt-in (`allow_subject_mismatch: true`). |
| `--output <dir>` | Also write a diff bundle: `diff.json`, `verdict.json`, `policy/evaluated-policy.json`. Never inside an existing trust-freeze bundle, the two inputs included. |
| `--format text\|json` | Output format (default `text`). `markdown` and `sarif` are not implemented in this version (exit `2`). |

Both inputs are verified first; if either fails, nothing is compared and the verification
result is printed instead. Artifacts are compared by id after the versioned normalization
rule set `trust-freeze/normalize/v1` has removed volatile values (timestamps, durations,
process ids, uptime). The same inputs, opt-in and policy give byte-identical output. A
baseline whose probes were all `captured`, or `not_applicable` with a reason, compared
with itself has no finding above `info` and exits `0`; the gaps of an approved incomplete
capture stay gaps in every diff.

**Source probe.** Every artifact names the probe that produced it in its `source` field.
That probe counts as *observed* in a bundle when it has exactly one result that is
`captured`, or `not_applicable` with a reason (the probe observed that nothing applies);
a source that is not a probe id counts as observed. Only what was observed on both sides
can be `removed` or `changed`: an artifact or attribute that the current bundle could not
observe is `not_observed`, never `removed` or `changed`, and its probe is reported as a
`collection_gap` as well.

**Capabilities** are compared separately from artifacts, by capability id, and only as
far as both bundles resolved them. A baseline without `state/capabilities.json` yields no
capability entry at all: nobody resolved capabilities when it was taken, so nothing in
the current bundle can be called new. A baseline with one and a current bundle without
yields `capability_not_observed` for every baseline capability.

The other direction has the **coverage guard**, and it reads the DECISIVE sources: the
sources whose artifact THIS comparison reported an entry for, because those are the ones
the difference rests on. A `capability_added` or a `capability_changed` becomes
`coverage_increased` when every decisive source comes from a probe the baseline did not
capture. What changed is then the collection depth and not the host, so
`baseline_gap_probes` names those probes and the built-in policy rates the entry `info`.
One decisive source on ground both runs could see keeps the entry at `capability_added`
or `capability_changed` at full severity, with `coverage_caveat_probes` naming the thin
probes beside it. The shape this is for: a public key capability whose account artifact
was in the baseline and whose key artifact was not, because that run could not read
`authorized_keys`. The account is not new; the reading is.

A capability whose source probes were ALL blind in the baseline is `coverage_increased`
too, decisive or not: the baseline covered none of the ground it stands on. Blind means
the probe produced no usable observation there: it left no single result, or its status
was `unsupported`, `unavailable`, `permission_denied`, `timeout`, `failed` or
`not_applicable`. A baseline probe with status `partial` did look and did report, so it
is not blind and a capability that rests on it keeps its kind. A capability whose sources
name no artifact of either bundle cannot be tied to a probe and is counted nowhere, since
the guard never invents a gap it did not measure; an entry with no decisive source at all
keeps its kind too.

**Change kinds**, in the sort order of the diff (then by artifact id, then by capability
id, then by probe id):

| Kind | Reported when |
|------|---------------|
| `subject_changed` | The baseline and the current bundle describe different devices (their subject ids differ). Exactly one entry, with `before_subject_id`, `after_subject_id` and `subject_mismatch_allowed`. |
| `added` | The artifact id exists only in the current bundle. |
| `removed` | The artifact id exists only in the baseline, and its source probe is observed in the current bundle. |
| `changed` | A compared field differs, or an attribute observed on both sides (present there, or absent under an observed probe) has different values. Names the changed attributes and fields, with before and after digests, never the values. |
| `not_observed` | The artifact id exists only in the baseline, or baseline attributes are missing from it, and its source probe is not observed in the current bundle. Names `probe_id` and `unobserved_attributes`. |
| `confidence_changed` | `provenance.confidence` differs. |
| `became_effective` | The state moves to `observed`. |
| `became_ineffective` | The state moves away from `observed`. |
| `capability_added` | The capability id exists only in the current bundle, AND at least one source this comparison found new or changed comes from a probe the baseline did capture (or the baseline covered some of the capability's ground while nothing decisive moved). Carries `capability_id` and `after_privilege`, and `coverage_caveat_probes` where a source probe was only `partial` in the baseline, or blind there beside a covered one. |
| `capability_removed` | The capability id exists only in the baseline, and every artifact it rests on was observed in the current bundle, so its absence was observed. |
| `capability_changed` | A field of the capability differs, and not every source this comparison found new or changed comes from a probe the baseline was blind to. Names the changed fields (`privilege`, `sources`, `state`, `attributes`, ...), with before and after digests, and `coverage_caveat_probes` where the baseline coverage was thinner than the current one. |
| `capability_not_observed` | A baseline capability could not be observed: an artifact it rests on is missing from the current bundle, or that bundle has no capability document. Never reported as removed. |
| `coverage_increased` | A `capability_added` or a `capability_changed` whose every DECISIVE source (a source whose artifact this comparison found new or changed) comes from a probe the baseline did not capture, or whose every source probe was blind there. The difference is not called drift; `baseline_gap_probes` names those probes. From the added direction the entry has an `after_digest` only; from the changed direction it keeps both digests and `changed_fields`. The mirror of `capability_not_observed`, so a diff between bundles of different collection depth does not become a wall of critical findings. |
| `applicability_changed` | A probe moves between `captured` and `not_applicable` with a reason, in either direction (`before_status`, `after_status`): the host changed, not the collection. |
| `collection_gap` | A probe of the current bundle is not `captured`, or a required probe has no result. |

Every `collection_gap` carries `required`, the recorded `status` (when there is one), the
probe's `reason` (when it gave one) and exactly one `cause`:

| `cause` | Meaning |
|---------|---------|
| `not_captured` | One result with another status: `partial`, `unsupported` (also a probe skipped with `--probe` or `--exclude-probe`), `unavailable`, `permission_denied`, `timeout` or `failed`. |
| `not_applicable` | `not_applicable` with a reason: complete for the capture, and still visible here. |
| `not_applicable_without_reason` | `not_applicable` without a reason. |
| `no_result` | A required probe has no result. |
| `duplicate_result` | More than one result for the probe. |
| `invalid_status` | A status that is not a known probe status. |

The diff document records `allow_subject_mismatch` (also when it is `false`) and `counts`
with the number of entries of every kind, zero included. Each finding of the verdict has
a stable id: the kind and the artifact id (`changed:device/os`), the capability id for a
capability entry, the probe id for `collection_gap` and `applicability_changed`, the
current subject id for `subject_changed`.

**Policy `trust-freeze/policy/default-v1`** (`fail_on: high`). Every change gets exactly
one finding with the highest severity of all rules that match it; a change no rule
matches gets `default_severity`, `info`.

What a policy judges changes with a new id, never with an edit of a published one, so the
one older policy is frozen and still selectable by id with `--policy`:
`trust-freeze/policy/default-v0` rates no capability entry at all, so under v0 even a new
root capability comes out with the default severity `info`. Use it only to reproduce a
verdict that was computed with it. The verdict of every diff records the id and the rules
digest of the policy that judged it, in `verdict.json`, and a diff bundle carries the
evaluated policy itself under `policy/evaluated-policy.json`.

| Change | Severity | Rule |
|--------|----------|------|
| `subject_changed` without the opt-in | `high` | `TF-POL-SUBJECT-CHANGED` |
| `subject_changed` with `--allow-subject-mismatch` | `info` | `TF-POL-SUBJECT-CHANGED-ALLOWED` |
| `collection_gap` of a required probe, every cause except `not_applicable` | `critical` | `TF-POL-GAP-REQUIRED` |
| `collection_gap` of an optional probe, every cause except `not_applicable` | `medium` | `TF-POL-GAP-OPTIONAL` |
| `collection_gap` with cause `not_applicable`, required or optional | `info` | `TF-POL-GAP-NOT-APPLICABLE` |
| `device/os` or `device/host` `changed` | `medium` | `TF-POL-DEVICE-IDENTITY` |
| any other `added`, `removed` or `changed` | `low` | `TF-POL-ARTIFACT-DRIFT` |
| `not_observed` | `low` | `TF-POL-NOT-OBSERVED` |
| `capability_added` or `capability_changed` whose privilege is `root`, `root-via-container-runtime`, `root-via-privileged-container`, `root-via-sudo` or `root-via-sudo-nopasswd` | `critical` | `TF-POL-CAPABILITY-ROOT` |
| any other `capability_added` | `high` | `TF-POL-CAPABILITY-ADDED` |
| any other `capability_changed` | `medium` | `TF-POL-CAPABILITY-CHANGED` |
| `capability_removed` or `capability_not_observed` | `low` | `TF-POL-CAPABILITY-GONE` |
| `coverage_increased` | `info` | `TF-POL-COVERAGE-INCREASED` |
| `applicability_changed` | `low` | `TF-POL-APPLICABILITY` |
| `confidence_changed`, `became_effective`, `became_ineffective` | `info` | `default_severity` |

So under default-v1 a diff of two different devices blocks by itself; with
`--allow-subject-mismatch` that finding no longer does, while every other finding keeps its
severity. A missing required probe blocks; a probe that is not applicable on this host and
says why does not.

**Own policy** (`--policy`, JSON or YAML; unknown fields are refused):

```yaml
schema_version: trust-freeze/policy/v1
id: example/policy-v1
fail_on: high                       # none | low | medium | high | critical
default_severity: info              # for a change no rule matches
rules:
  - id: EX-GAP-TIMEOUT
    severity: high
    match:                          # every condition that is set must hold
      change_kinds: [collection_gap]
      required: false               # with change_kinds [collection_gap] only
      gap_causes: [not_captured]    # with change_kinds [collection_gap] only
      gap_statuses: [timeout]       # with change_kinds [collection_gap] only
  - id: EX-FLEET-BASELINE
    severity: low
    match:
      change_kinds: [subject_changed]
      subject_mismatch_allowed: true  # with change_kinds [subject_changed] only
  - id: EX-ROOT-CAPABILITY
    severity: critical
    match:
      change_kinds: [capability_added]
      privileges: [root, root-via-sudo, root-via-sudo-nopasswd]  # capability kinds only
```

`change_kinds` is required and must not be empty. `artifact_ids` restricts a rule to exact
artifact ids and cannot be combined with `collection_gap` or a capability kind, neither
of which has an artifact id. `privileges` is allowed only when every change kind of the
rule is a capability kind; it matches the privilege the current bundle observed, and the
baseline privilege where the current bundle has no capability. A `gap_causes` or
`gap_statuses` list must not be empty and may name only known causes and probe statuses;
a gap without a status (`no_result`, `duplicate_result`, `invalid_status`) never matches
`gap_statuses`.
Between rules of the same severity the earlier one names the finding. The rule id
`default_severity` is reserved.

Exit: `0` threshold not reached · `1` threshold reached (`drift_threshold_exceeded`), an
input failed verification (`verification_failure`), or the run failed (`execution_error`)
· `2` usage.

#### `trust-freeze report`: project a bundle onto the JSON report

| Flag | Purpose |
|------|---------|
| `--input <dir>` | Capture, baseline or diff bundle (required). It must pass its integrity check. |
| `--output <file\|dir>` | Report file to create (required); an existing directory gets `report.json`. Never overwritten, never inside the input bundle or any other trust-freeze bundle. Mode `0600`, because a report can carry the host name. |
| `--format json` | Report format (default `json`). `markdown` and `sarif` are not implemented in this version (exit `2`). |

The report (schema `trust-freeze/report/v1`) is a pure projection of the bundle and
decides nothing. It checks the input's integrity (manifest, sizes, digests, layout) and
evaluates nothing else: no signature, no key trust, no expiry, and it reads no clock, so
the report of an unchanged bundle has the same bytes whenever it is made. For a baseline
the `signature` section always reads `{"result": "not_evaluated", "verify_with":
"skillctl trust-freeze verify"}`; the trust decision is `verify --trusted-key`, and a
report is never evidence that a baseline is valid. Standard output carries a JSON status
with `result_class`, the input, the same `signature` section for a baseline, and the
report's SHA-256. What a report carries is internal host data (see Privacy above).

**Capabilities.** The report of a capture or baseline projects `state/capabilities.json`
under `capture.capabilities`: the resolver that ran, one entry per capability with `id`,
`subject_id`, `action`, `resource`, `effect`, `privilege`, `exposure`, `scope`, `state`,
`confidence`, its `attributes` and its `sources`, and the resolver's own `diagnostics`
beside them, so an empty list is never read as "this host grants nothing". The entries are
ordered by how far the privilege reaches (`root`, then `root-via-sudo-nopasswd`, then the
two container paths, then `root-via-sudo`, then anything unknown, then `user`), and by id
within a rank. That order is presentation, not judgement: the report still evaluates
nothing, and a bundle without `state/capabilities.json` has no `capabilities` key at all.

Exit: `0` report written · `1` input failed its check (`verification_failure`) or the
file could not be written (`execution_error`) · `2` usage.

#### `trust-freeze`: how probes run, and known limits

- **Commands** run as executable plus argument vector, never through a shell, resolved
  only in `/usr/bin`, `/bin`, `/usr/sbin`, `/sbin`, on Linux followed by `/snap/bin`
  (Windows: the system directory the OS reports). `/snap/bin` is where snapd puts the
  entry point of an installed snap, and on Ubuntu `docker` is commonly one; it comes
  last, so a distribution package wins over a snap of the same name. The caller's `PATH`
  is never read. The environment is only the probe's allowlist plus `LC_ALL=C` and `TZ=UTC0`;
  the working directory is `/` (Windows: the Windows directory). `sudo`, `su`, `doas`,
  `pkexec`, `run0`, `runuser` and `runas` are refused by name, path or symlink target.
  On Unix every tool runs in a session and process group of its own without a
  controlling terminal, so a password prompt fails at once, and at the timeout the whole
  group is killed. On Windows the started process and every descendant traceable by
  parent pid are killed; a descendant started by a service or broker, or one that runs
  elevated, is not.
  Ctrl-C and SIGTERM cancel a running capture the same way.
- **Output** is capped per stream (1 MiB stdout, 64 KiB stderr by default). A truncated
  output is recorded and makes the probe `partial`, on two levels: the capture engine
  lowers any probe whose run hit the cap, and each Linux probe additionally reads the
  flag itself and adds an `output_truncated` diagnostic that names the stream, the cap and
  what the bundle therefore does not know. A list that was cut also says so in its own
  artifact (`network/listeners.listener_list_truncated`,
  `container/runtime/<name>.container_list_truncated`), so no reader takes the count
  beside it for the whole host.
- **Volume** is capped per probe, so a large host yields a bounded bundle: 5000 packages,
  4096 listeners, 4096 mount points, 2048 containers, 2000 accounts and 2000 groups, 512
  units in the `systemctl show` selection, 64 accounts and 64 keys per account for
  `authorized_keys`. Every cap that bites is a `volume_capped` (or family specific)
  diagnostic and makes the probe `partial`; the count the tool reported stays in the set
  artifact. `docker inspect` is asked in batches of 40 containers, the way `systemctl
  show` is, so no argument vector grows with the host. Everything written is redacted first: private key blocks, bearer and
  authorization values, cloud and chat tokens, JWT-shaped strings, values under keys such
  as `password` or `token`, and the home directory in any letter case or separator
  spelling (for a Windows home also its WSL form `/mnt/<drive>/...`). A value that
  cannot be redacted is dropped and the probe is at least `partial`. Every evidence file
  passes the capture's redactor once more before it is written, together with every
  secret taken from the arguments of that probe's commands, so a secret one command
  receives and another prints is removed as well. An evidence file refused by the file
  size or file count limit makes the probe `partial`.
- **The replacement marker** is `[REDACTED_<class>]`, one token of letters, digits,
  underscores and the two brackets. It deliberately carries no colon, tab, comma,
  semicolon, equals sign, space or line terminator, because the probes parse the same
  output by field position afterwards: colon separates the fields of `getent passwd` and
  `getent group`, tab those of `dpkg-query` and `ss`, comma a group member list, the
  equals sign an `id` token, space every whitespace separated table. A marker that
  carried one of them would turn one field into two and the parser would refuse the
  record, so the class of the finding is spelled with an underscore and the record
  keeps its shape.
- **A value that cannot be a secret is not replaced.** The rule that replaces a value
  because its KEY sounds like a credential has a second half, the value itself. A short
  token from a closed set of configuration answers (`yes`, `no`, `true`, `false`, `none`,
  `any`, `all`, `default`, `prohibit-password`, `without-password`,
  `forced-commands-only`, an answer of the `yes-with-...` family, a plain integer of at
  most ten digits, and a duration such as `90s` or `1h30m`) is what a setting answers,
  not a credential, and it stays. Everything else keeps being replaced, so a key named
  `password_hash` with a 60 character value is still removed. Measured on an elevated
  Ubuntu bastion capture: `passwordauthentication`, `permitemptypasswords` and the
  `nopasswd` flag of a sudo rule came out as `[REDACTED_password]`, so the bundle could
  not say whether password login was allowed, and the capability resolver, which reads
  that flag, rated an unrestricted passwordless root grant as `root-via-sudo`.
- **A probe says what its own fields are.** Where a probe knows the semantics of a field,
  it records the class in the artifact (`attribute_classes`): `policy` for the sshd
  directive set of `ssh/sshd/declared` and `ssh/sshd/effective` and for the attributes of
  a `sudo/rule/...` artifact, `sensitive` for a field that must be replaced whatever its
  name and its shape. A `policy` field is exempt from the key name rule only: every value
  pattern still runs over it, so a private key block under a policy field is still
  removed. The class is recorded only where the key name rule would otherwise fire, so
  most artifacts carry none. It is written into the bundle, so a reader can see why a
  value stands there in clear, and the manifest covers it like every other byte; the
  per-artifact digest keeps covering identity and attributes only.
- **A path segment is not a key.** A name glued to a forward slash is the last segment of
  a path, and what follows the colon after it is a message, not its value. Measured on the
  recorded refusal of the trial host, where `cat: /etc/sudoers.d/alice-nopasswd:
  Permission denied` became `... [REDACTED_password] denied` and hid why the file was not
  read. A backslash separated name keeps being read as a key.
- **Architecture.** `arch` comes from `uname -m` (linux, darwin) and from
  `IsWow64Process2` (windows). On macOS an `x86_64` answer is checked with
  `sysctl.proc_translated`: `1` means Rosetta 2 translates skillctl, so `arch` is `arm64`
  and a `value_derived` diagnostic says so; an Intel Mac answers "unknown oid". A Linux
  process under user-mode emulation (for example qemu-user) sees the emulated machine in
  `uname -m`.
- **Identity caveats.** On macOS `os_version` includes the Rapid Security Response tag
  when one is installed (`13.4.1 (c)`), so installing or removing one changes `device/os`.
  The macOS host name can follow the network when no HostName is configured, which changes
  `device/host` and the subject id between captures. On a Linux rolling release (Arch:
  `BUILD_ID=rolling`, no `VERSION_ID`) `os_version` is `not_applicable`. In a container or
  under WSL, os-release describes the image while `uname -r` reports the host or VM
  kernel. On Windows 11 the registry `ProductName` still says Windows 10; `os_name` is
  derived from the build number, the evidence keeps the registry's own values, and a
  `value_derived` diagnostic states the rule.
- **Windows file permissions.** Bundle files are created with mode `0600` and directories
  `0700`, which Windows ignores: on Windows a bundle inherits the ACL of the directory it is
  written into. Write bundles below a directory only you can read. Go reports cloud-sync
  placeholders and similar reparse points as irregular files, so a bundle inside a
  cloud-synced folder can fail verification with `not_regular`; copy it to a local
  folder first.
- **Moving a bundle to another machine.** A bundle verifies only as it was written: it
  rejects additions, so verify reports every file that is not in its manifest as `extra`
  and fails, whatever the file's name, and a changed byte as `digest_mismatch`. That
  strictness is intended. Move bundles with a method that adds no file and changes no
  byte, and run `verify` on the target afterwards:
  - `tar`. On macOS create the archive with `COPYFILE_DISABLE=1 tar -cf bundle.tar <dir>`.
    Without it the macOS `tar` stores an AppleDouble `._<name>` entry next to every file
    and directory that carries extended attributes (on macOS 15 even ordinary files and
    directories can carry `com.apple.provenance`), and `tar` on Linux or Windows unpacks
    those entries as files.
  - `rsync -a` without the option that copies extended attributes (`-X` in rsync 3,
    `-E` in the rsync that ships with macOS).
  - `cp -R -X` on macOS (`-X`: do not copy extended attributes or resource forks).

  Two macOS habits add files that make verify fail with `extra`: copying to a volume
  without extended-attribute support (FAT, exFAT, many network shares) writes `._<name>`
  files, and Finder can write a `.DS_Store` into a bundle folder it has shown. A git
  checkout that converts line endings changes bytes. Removing an added `._<name>` or
  `.DS_Store` file after checking what it is restores the bundle, because verify then
  checks every manifested byte again; verify itself never skips such a file.
- **Known gaps of this version.** `doctor` checks the Claude roots, the output location
  and per-probe tools (see its own section); what it cannot determine stays
  `not_checked` with a reason, and a probe that does not name the executables it uses is
  one such reason. `diff` emits one change list with per-kind `counts`, not separate system,
  artifact, capability and collection-gap sections. Capabilities are resolved on linux
  only, and only from sudo rules, group membership and authorized keys, so a privilege
  that rests on anything else is not in the document. `report --format markdown|sarif` and
  `diff --format markdown|sarif` are not implemented (exit `2`).

### `publish`: admit / attest / revoke via ER1 (`self` registry)

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
| `-bundle` | Path to a pre-built `.skb`. If empty, the skill dir is packed in place. The manifest inside it decides the kind; a contradicting `--kind` is refused. |
| `-kind skill\|agent` | Bundle kind (SPEC-0432). `agent` packs ONE definition file onto the agent shelf. Must agree with the bundle manifest when both are present. |
| `-agent-file` | `[--kind agent]` Path to the agent definition. Default: `~/.claude/agents/<name>.md`. |
| `-skill-dir` | Skill directory. Default: `~/.claude/skills/<name>`. |
| `-version` | Skill version (overrides SKILL.md frontmatter). Required for admit. |
| `-digest` | `[--attest\|--revoke]` existing bundle digest (`sha256:<hex>`). Derived from `--bundle` if empty. |
| `-level green\|yellow\|red` | `[--attest]` governance level (default `green`). |
| `-rationale` | `[--attest\|--revoke]` one-line rationale. |
| `-reason` | `[--revoke]` short reason code (e.g. `key-compromise`, `deprecated`). |
| `-registry` | Registry spec: `self` (recommended) or `er1://…`. HTTP registries route through `install`. Default `self`. |
| `-er1-target prod\|stage\|local` | ER1 target (default `prod`). |
| `-er1-context` | ER1 context (default `skills`). |
| `-identity` | Author/registry identity id stamped into the event and tags. **Required.** |
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

Exit: `0` ok · `1` generic / network / ER1 error · `2` usage.

---

### `pull`: the 5-gate gauntlet against `self`

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
| `-kind skill\|agent` | Restrict to one bundle kind (SPEC-0432). Empty pulls both shelves; an unknown value is refused with exit `2`; only the `er1` self registry supports it. |
| `-digest` | Filter: only this exact bundle digest (`sha256:<hex>`). |
| `-since` | Best-effort lower bound on `occurred_at` (RFC3339). |
| `-skills-dir` | Where to install skills. Default `~/.claude/skills`. |
| `-trust-roots` | SPEC-0225 trust-roots YAML. Default `~/.claude/trust-roots.yaml`. |
| `-registry self` | Registry spec. Only `self` / `er1://…` here; HTTP routes through `install`. |
| `-er1-target prod\|stage\|local` / `-er1-context` | ER1 target/context (defaults `prod` / `skills`). |
| `-emit-installed` | After install, POST a `BundleInstalledEvent` so the other machine sees it. |
| `-identity` / `-key` | `[--emit-installed]` identity + signing key for the install event. **Required.** (`-identity` only, and only together with `--emit-installed`.) |
| `-no-checkpoint` | Don't append a SPEC-0213 session checkpoint after install. |
| `-verbose` | Print one line per per-gate decision. |

```bash
skillctl pull --verbose
skillctl pull --install --trust-mode --dry-run-install
skillctl pull --install --trust-mode --confirm-install --dry-run-install-token <sig>
```

Exit: `0` all bundles staged · `7` NULLTREFFER: the query matched nothing, which is deliberately not success (BUG-0254: an empty run was indistinguishable from a run with nothing to do, and a gate that reports green while checking nothing creates trust nothing answers to) · `2` usage or a refused `--install` precondition (missing `--trust-mode`, a missing / expired / forged G-23 token) · `1` bundles were skipped for MORE THAN ONE reason (no single number can name two causes; read the per-row gate) · one skipped gate maps to ITS number: `12` envelope / registry not trusted, `10` digest, `11` bundle signature, `13` governance below minimum, `6` revoked. `--install` returns `10` when the extracted bundle's `CHECKSUMS` manifest stops describing it (SPEC-0188 §7 step 8). Measured against `skipExitCode` / `gateExit` in `cmd/skillctl/pull_cmds.go`.

---

### `registry`: inspect the `self` registry

```bash
skillctl registry <ls|show> [flags]
```

**`registry ls`**: list bundles in the `self` registry, grouped by skill.
Flags: `[--latest] [--skill <name>] [--er1-target …] [--er1-context …]`.

**`registry show`**: show the full event timeline (admit / attest / revoke / install) for
one skill or one digest.
Usage: `registry show <name | sha256:<hex>> [--er1-target …] [--er1-context …]`.

```bash
skillctl registry ls --latest
skillctl registry show my-skill
skillctl registry show sha256:<hex>
```

---

### `drift`: what this machine carries vs the catalog

```bash
skillctl drift [flags]
```

Compares every locally installed artifact (skills and agents, SPEC-0432) against the
latest catalog entry in the `self` registry and prints one row per artifact with a
verdict: `aktuell`, `veraltet`, `ohne Nachweis` (no provenance sidecar vouches for it;
the normal case on the machine where artifacts are authored), `fehlt lokal`,
`nicht im Katalog`. An artifact without a sidecar is reported as unvouched, never
silently folded into "fine".

| Flag | Purpose |
|------|---------|
| `-kind skill\|agent` | Restrict to one kind. Empty compares both. |
| `-only-findings` | Print only rows that are not `aktuell`. |
| `-er1-target prod\|stage\|local` | ER1 target (default `prod`). |
| `-er1-context` | ER1 context (default `skills`). |

```bash
skillctl drift
skillctl drift --kind agent --only-findings
```

Exit: `0` nothing stale, missing, or uncataloged · `1` at least one `veraltet` /
`fehlt lokal` / `nicht im Katalog` row, or a transport error · `2` usage. `ohne
Nachweis` alone does not fail the run: it is a statement about missing vouching,
not about a mismatch. Measured against `runDrift` in `cmd/skillctl/drift_cmds.go`.

---

### `verify-hook`: the fail-closed Claude Code gate

```bash
skillctl verify-hook
```

A `PreToolUse(Skill)` hook: it reads a hook event on **stdin**, verifies the SPEC-0188 §7
chain, and emits an allow/deny decision as JSON on stdout. **Fail-closed**: if it cannot read
or verify the event, it denies. Wire it in your Claude Code settings as a hook; do **not** run
it by hand. Running it interactively prints a fail-closed deny (unreadable stdin) and exits
`2`.

**Revocation freshness is fail-closed at the gate too (FR-0045 D4).** Beyond the trust chain,
the hook enforces the SPEC-0279 freshness contract: an **emergency deny**, or a revocation
snapshot too stale to trust for the requested action (`bundle_revocation_stale` /
`agent_revocation_stale`, SPEC-0279 R3/R5), denies rather than allows. This is the runtime
edge of the FR-0045 kill-switch: because the revocation HEAD is checked against a pinned
registry key, a tampered, rolled-back, or forged feed is refused, not silently trusted.

**The process always exits `2`**, both for an allow-blocking deny and for the unreadable-stdin
refusal, because `2` is what Claude Code reads as "block this tool call". The number that says
WHY rides the decision's `refusal_code` instead, and it is one of exactly four, measured
against `cmd/skillctl/verify_hook_cmds.go`:

| `refusal_code` | Meaning |
|---------------:|---------|
| `17` | The bundle is revoked, or an emergency deny-list names it. |
| `22` | The revocation snapshot is too stale (or its signed HEAD did not verify) to answer for a high-risk invocation. |
| `25` | `offline_unverifiable_managed`: a legacy managed install with no offline metadata, while `offline_policy` state-gates the online fallback. |
| `28` | `offline_locked`: a managed-enterprise host with NO trust basis at all. |

`26` belongs to `enforce` and `27` to `guard-path`, not here: those two verbs are separate
gates with the same exit-2-plus-`refusal_code` convention. A deny for any other cause carries
the §7 chain's own code (`10`-`17`, `20`, `22`, `23`) in its message.

**The network is touched only on one narrow path, and every request on it is bounded at 8
seconds** (`verifyHookTimeout`, `cmd/skillctl/verify_hook_cmds.go`). The path is taken when
all of the following hold: the skill is managed, the verdict cache misses, the install has NO
stashed offline verification metadata (a legacy install: `skillctl install <skill>` stashes
it), and the enterprise offline state-gate does not suppress the fallback. Anything else,
including every allow from the verdict cache or the offline chain, is decided without a
registry round trip. The offline fast path is SPEC-0247 P1; the timeout is the bound on the
P0.1 fallback that remains.

Read `verifyHookTimeout` as a per-request bound, not a budget for the call. It is the
`Timeout` field of the `http.Client` that `install.HTTPClientOf` builds, so Go applies it to
each request separately, and that path issues at least two: `GetBundleMeta`, then
`GetIdentity` for the author, the second skipped only when the trust root sets
`identity_keys_authorized: pinned` (`pkg/skillctl/verify/verify.go`, the pinned-author
branch). Budget the worst case as 8 seconds per request, not 8 seconds in total.

```json
// settings.json (excerpt): wire it as a PreToolUse(Skill) hook
{ "hooks": { "PreToolUse": [ { "matcher": "Skill", "hooks": [ { "type": "command", "command": "skillctl verify-hook" } ] } ] } }
```

Exit: `0` allow · `2` every deny, and the unreadable-stdin refusal. The cause rides the
decision's `refusal_code`: `17`, `22`, `25` or `28`, per the table above.

---

### `gate-stats`: summarise gate decisions

```bash
skillctl gate-stats [--since <168h|YYYY-MM-DD>] [--json]
```

Summarises `gate-audit.jsonl`: decisions, top blocks, cache-hit rate.

| Flag | Purpose |
|------|---------|
| `-since` | Only events newer than this: a Go duration (e.g. `168h`) or a date (`YYYY-MM-DD`). |
| `-json` | Emit the summary as stable JSON. |

```bash
skillctl gate-stats --since 168h
skillctl gate-stats --since 2026-06-01 --json
```

---

### `auditlog`: audit-subsystem observability (SPEC-0403 §8)

```bash
skillctl auditlog <status|test|flush> [--json]
```

The observability CLI for the audit event layer. It has its **own verb stem** and its
**own exit space `0/1`** (`0` healthy/accepted/drained, `1` unhealthy/refused/drain error;
`2` is a usage error). This is deliberate: `skillctl audit` (above) is the antivirus-style
**posture** verb with exit codes `0/2/3`, and a health finding must never be read as a
posture finding. `auditlog` is intended to be the first entry in the FR-0113 verb register.

| Subcommand | Purpose |
|------------|---------|
| `status` | Report subsystem health: enabled, mode, sink type + path, outbox pending, spool pending, last event. Exit `0` healthy / `1` unhealthy. |
| `test` | Emit ONE clearly-synthetic `skillctl.audit.v1` event through the real default sink and confirm it was accepted. Exit `0` accepted / `1` refused. |
| `flush` | Reconcile the local spool queue into the durable outbox (the local half of `sync`, no broker egress) and report pending before/after. Exit `0` / `1`. |

| Flag | Purpose |
|------|---------|
| `-json` | Emit the result as stable JSON. |

There is **no Kafka**: a direct broker sink is FR-0112 and EC-blocked (§7.2), so `status`
reports only the sink and outbox/spool that exist today and never fabricates a broker
endpoint. `flush` reaches only the local spool (REQ-6.10b); network egress is `skillctl sync`
(default-OFF). A transport failure is surfaced as an observable `audit.sink.fail` /
`audit.queue.flush` event on stderr, never re-reported through the sink that failed (no
recursive error loop, REQ-8.2).

Exit: `0` healthy / accepted / drained · `1` unhealthy / refused / drain error · `2` usage or
flag error, including an unknown subcommand (`auditlogExitUsage`,
`cmd/skillctl/auditlog_cmds.go`). The `0/1` half is the health verdict, and it is that half
that must never be read as `audit`'s posture verdict; the `2` is the ordinary usage code every
verb has.

```bash
skillctl auditlog status
skillctl auditlog status --json
skillctl auditlog test
skillctl auditlog flush
```

---

### `pin`: make the gate un-deletable via managed settings (SPEC-0247 §7.3)

```bash
skillctl pin <generate|status|install> [flags]
```

Emits (and optionally stages) the Claude Code `managed-settings.json` that pins the
`verify-hook` trust gate. Without `--strict` the gate is already un-deletable by
non-privileged users and its deny is absolute, while the operator's own hooks keep working;
root, or anyone who can write the managed-settings directory, can still remove it.

**`pin generate`**: print the managed-settings JSON. **`pin install`**: stage the file and
print the sudo runbook (as root, `--confirm` writes it). Both take:

| Flag | Purpose |
|------|---------|
| `--binary <path>` | Absolute path to `skillctl` (default: this binary). |
| `--strict` | Add `allowManagedHooksOnly: true`: the full CISO lockdown, which also **disables every other user/project hook**. |
| `--harden` | Imply `--strict` **and** block `claude --dangerously-skip-permissions`. |
| `--enterprise` | Add `skillctlEnterprise: true`: enables the R-7.2 offline `locked` state. |
| `--require-local-audit` | Add `skillctlRequireLocalAudit: true` (implies `--enterprise`) and wire the PreToolUse gate to `skillctl enforce`, the only verb that consumes the flag: R-8.2, fail closed (exit 26) when an allow cannot be recorded. |
| `--state-gate-fallback` | Add `skillctlStateGateFallback: true` (implies `--enterprise`): R-1.4 P2: keep the hot path strictly local, with no online fallback while disconnected. |
| `--out <file>` | Write the JSON to a file instead of stdout (`generate`). |
| `--path <file>` | Target managed-settings path (`install`), or the path to inspect (`status`). |
| `--confirm` | `install` only, and only as root: actually write the file. |

**`pin status`**: report whether the gate is pinned. Takes `--path <file>` and `--json`.

Exit: `0` ok (`generate` printed, `status` found the gate pinned, `install --confirm` wrote
it as root) · `1` any error, including an unknown subcommand · `2` `pin status` found the gate
NOT pinned · `3` `pin install` as a non-privileged user: the merged file was staged and the
sudo runbook printed, nothing was written. Measured at the binary against
`pinExitNeedPrivMsg` in `cmd/skillctl/pin_cmds.go`.

```bash
skillctl pin generate --harden --enterprise
skillctl pin status --json
```

---

### `guard-path`: the skill-dir access guard

```bash
skillctl guard-path [flags]
```

The PreToolUse companion to `verify-hook`: it sees an access to a skill directory and, by
default, **allows it and records it**. Denying is opt-in, because a default-deny here would
break every unmanaged skill dir.

| Flag | Purpose |
|------|---------|
| `--deny` | Opt in to DENY (exit `2`) a skill-dir access instead of audited-allow. |
| `--explain` | Print the honest scope + the coverage gaps, then exit. Read this before you rely on it. |
| `--home <dir>` | Home-dir override (default `$HOME`). |

```bash
skillctl guard-path --explain
```

Exit: `0` allow (the default, and every allow) · `2` an opt-in `--deny` blocked the access, or
a usage error. The signed guard event carries `27` (`sidechannel_denied`) as the refusal code;
the process status stays `2`, because `2` is what blocks a `PreToolUse` call.

---

### `session-baseline`: informational SessionStart context (SPEC-0317 R-7)

```bash
skillctl session-baseline [flags]
```

Prints the named offline state, `online` / `degraded` / `offline` / `locked`, plus the
advisory-until-pinned banner. It is a **pure read that gates nothing**.

| Flag | Purpose |
|------|---------|
| `--online` | Assert the registry is reachable. `SessionStart` deliberately does **not** probe the network by default. |
| `--managed-settings <file>` | `managed-settings.json` path override (default: the platform path). |
| `--trust-roots <file>` | Trust-roots path override (default `~/.claude/skill-trust-roots.yaml`). |
| `--home <dir>` | Home-dir override. |
| `--json` | Emit JSON. |

Exit: `0` the state was printed · `1` every failure, INCLUDING a flag-parse error.

There is no usage code here. The verb gates nothing, so it never separates a bad flag from any
other failure; every path in `cmd/skillctl/session_baseline_cmds.go` returns one of the two.

---

### `sync`: drain the enforcement-evidence outbox (SPEC-0317 R-5)

```bash
skillctl sync [--once | --daemon] [flags]
```

Drains the device-signed `audit_events` outbox to the KafShield ingest. It is a **separate
process, never on the hook path**, and it is distinct from `sync-usage` (the skill-telemetry
drain). Rows are marked synced **only** against a valid signed durable-seq ack, so a
lying or replaying endpoint cannot make evidence disappear locally.

| Flag | Purpose |
|------|---------|
| `--once` | Drain pending evidence once, then exit. |
| `--daemon` | Loop the drain on `--interval`, with a signal-handled shutdown. |
| `--interval <dur>` | Daemon loop interval (default `1m0s`). |
| `--batch <n>` | Max rows per drain batch (default `100`). |
| `--endpoint <url>` | Ingest endpoint base URL (https). **Default OFF**: evidence stays local-only until you set it. |
| `--backend <name>` | Audit export backend by name (known: `er1`). **No default**: enabling egress means naming a backend (SPEC-0455 D1). Env: `SKILLCTL_AUDIT_BACKEND`; the flag wins. |
| `--ingest-pubkey <path>` | PEM (SPKI) ed25519 public key that signs durable-seq acks. **Required to mark rows synced.** |
| `--log-id <id>` | Log id the durable-seq signature is bound to (default `skillctl-local`). |
| `--insecure` | Skip TLS verification. Loopback endpoints only. |

Egress needs BOTH a named backend and its endpoint. An endpoint without a named
backend is refused loudly with exit `40` (`audit_backend_config`); the pre-SPEC-0455
endpoint-only configuration is never mapped silently onto a backend (REQ-5.1a).
With neither set, `sync` stays local-only and exits `0` as before.

```bash
skillctl sync --once --backend er1 --endpoint https://ingest.example.com --ingest-pubkey ingest.pub
```

---

### `agentid`: offline-verifiable agent identity

```bash
skillctl agentid <issue|verify|show|revoke> [flags]
```

An **AgentID** is an owner-signed mandate (SPEC-0277): *this agent may use these skills for
these intents*. It verifies **offline** against pinned owner/approver keys.

**`agentid issue`**: build + owner-sign a mandate.

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

**`agentid verify`**: verify a mandate offline.

| Flag | Purpose |
|------|---------|
| `--bundle <agentid.json>` | The mandate to verify. |
| `--offline` | Network-free verification. |
| `--trust-roots <file>` / `--registry <url>` | Pinned keys / registry disambiguation. |
| `--revocations <file>` / `--checkpoint <file>` / `--emergency <file>` | Signed lists enforcing SPEC-0279 freshness. |
| `--json` | Emit the result as JSON. |

**`agentid show`**: print owner, grant, expiry, fingerprints, signatures:
`skillctl agentid show <agentid.json>`.

**`agentid revoke <agent-id>`**: add `agent:<id>` to a signed, offline revocation list
(SPEC-0276).

| Flag | Purpose |
|------|---------|
| `--reason <text>` | Why the mandate is revoked. |
| `--registry <url>` | Registry the list speaks for. |
| `--key <path>` | Signing key for the revocation list. |
| `--out <list.json>` | Where to write the signed list. |
| `--epoch <n>` | Epoch to stamp. `0` (the default) means auto: bump the existing list's epoch by 1, or start at 1. The epoch is what makes a rolled-back list detectable. |

```bash
skillctl agentid issue --owner id:you@m3c --owner-key mykey.priv \
  --for-agent agent-42 --skills my-skill --intents summarize --out agentid.json
skillctl agentid verify --bundle agentid.json --offline
skillctl agentid show agentid.json
skillctl agentid revoke agent-42 --reason compromised --registry https://aims.example.com/api/skills
```

Exit (`verify`): `0` ok · `11` owner-sig/not-pinned · `20` approver-floor · `21` expired ·
`17` revoked/emergency · `12` registry-not-pinned · `22` revocation-stale · `1` other · `2` usage.

---

### `translog`: L1 transparency log

```bash
skillctl translog <append|sth|prove|verify|consistency|witness> [flags]
```

A local RFC-6962 Merkle log (SPEC-0278, stdlib-only). L1 makes equivocation/withholding
**detectable**, not impossible. Event *data stays off the log*, only the signed event's
digest is appended. The default log file is `~/.claude/skillctl/transparency-log.jsonl`
(`--log` to override; `--log-id` default `skillctl-local`).

**`translog append <type> <digest>`**: append an event, where `type` ∈
`admit | attest | revoke | agentid-issue | agentid-revoke` and `digest` is
`sha256:<64 lowercase hex>` of the already-signed event.

| Flag | Purpose |
|------|---------|
| `--subject <s>` | Optional event subject (skill name, agent id, …) recorded alongside the digest. |
| `--log` / `--log-id` | Log path / log id override. |

**`translog sth`**: show / sign the current tree head.

| Flag | Purpose |
|------|---------|
| `-key` | Log ed25519 private key (PEM). If set, sign the head into an STH. |
| `-log` / `-log-id` | Log path / id. |

**`translog prove <digest>`**: emit an offline inclusion receipt.

| Flag | Purpose |
|------|---------|
| `--key <path>` | Log ed25519 private key (PEM) used to sign the head the receipt is against. **Required.** |
| `--out <file>` | Write the receipt here (default: stdout). |

**`translog verify`**: offline inclusion check.

| Flag | Purpose |
|------|---------|
| `--receipt <file>` | Inclusion receipt JSON, as produced by `prove`. **Required.** |
| `--log-pubkey <path>` | Pinned log ed25519 public key (PEM SPKI). **Required**: an unpinned key would verify nothing. |

**`translog consistency`**: verify the log is append-only between two heads.

| Flag | Purpose |
|------|---------|
| `--sth1 <file>` | The earlier (smaller) STH JSON. **Required.** |
| `--sth2 <file>` | The later (larger) STH JSON. **Required.** |
| `--proof <json>` | Consistency proof: a JSON array of hex hashes. **Required.** |

**`translog witness`**: cross-witness STHs to detect a split view.

| Flag | Purpose |
|------|---------|
| `--sths <file>` | JSON array of STHs collected from different witnesses. **Required.** |
| `--log-pubkey <path>` | Pinned log public key every STH must verify against. **Required.** |

```bash
skillctl translog append admit sha256:<hex> --subject my-skill
skillctl translog sth --key ~/.config/m3c/skill-keys/log.priv
skillctl translog prove sha256:<hex> --key ~/.config/m3c/skill-keys/log.priv --out receipt.json
skillctl translog verify --receipt receipt.json --log-pubkey log.pub
skillctl translog witness --sths sths.json --log-pubkey log.pub
```

Exit: `translog verify` → `0` ok · `23` not-included · `1` other · `2` usage.
`translog witness` → `0` consistent · `24` split-view-detected · `1` other · `2` usage.
`translog consistency` → `0` consistent · `25` an append-only rewrite was detected · `1` other · `2` usage.

---

### `session`: session-state in ER1 (SPEC-0213)

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
| `-summary` | Close summary (verbatim: your words). |
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

### `project`: PLM project context (SPEC-0214)

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

### `awareness`: the admission bridge (SPEC-0195)

```bash
skillctl awareness <sync|verify|reset> [flags]
```

**`awareness sync`**: admit local skills to a registry by scanning (or reading a saved scan).
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

**`awareness verify`**: read back per-session admissions.
Usage: `skillctl awareness verify [--session TAG] [--registry URL]`.

**`awareness reset`**: delete admit-from-scan docs scoped to a `session_tag`. Destructive,
so it is a **G-23 two-step**: the preview issues a short-lived token and the deletion is
refused without it.

| Flag | Purpose |
|------|---------|
| `--dry-run-reset` | Step 1: preview the affected docs and mint a 5-minute token. Deletes nothing. |
| `--dry-run-reset-token <token>` | Step 2: the token from step 1: required to confirm the destructive call. |
| `--confirm-reset` | Step 2: required alongside `--dry-run-reset-token` to actually DELETE. |

```bash
skillctl awareness sync --source claude --dry-run
skillctl awareness sync --confirm --require-intent
skillctl awareness verify --session skill-awareness/host/2026-07-02
```

---

### `intent`: declare / show a bundle's SPEC-0196 intent

```bash
skillctl intent <declare|show> [flags]
```

**`intent declare <skill-name|@digest>`**: patch the `intent` block of a previously-admitted
bundle, replacing the awareness `UNKNOWN` sentinel with a real declaration. Requires
`--confirm` to issue the PATCH; typed data-scope via `--data-scopes` (repeatable JSON).

| Flag | Purpose |
|------|---------|
| `--from-yaml <file>` | Read the whole intent + `data_dependencies` block from a YAML file, instead of declaring it flag by flag. |
| `--governance-intent green\|yellow\|red` | Bundle governance intent: checked against the §3.3 `destructive_green` cross-rule. |
| `--human-review-required true\|false` | Author claim: this skill needs human review beyond a governance attestation. |
| `--subprocess <list>` | Comma-separated subprocess allowlist (e.g. `pandoc,git`). |

Exit codes: `0` ok · `1` generic/network · `2` usage · `18` intent inconsistent with
`data_dependencies` (SPEC-0196 §3.3).

**`intent show <skill-name|@digest> --registry URL`**: print the declared intent +
`data_dependencies`. A scope is shown as **AUTHORITATIVE** only when the local `.skb`'s author
signature is verified against a **pinned** trust-root key (`--bundle` + the full verify
chain); a bare digest match is `UNVERIFIED`. `--json` for machine output.

```bash
skillctl intent show my-skill --registry https://aims.example.com/api/skills
skillctl intent declare my-skill --data-scopes '{"id":"…","kind":"local_fs","access":"read","scope":"…","reason":"…"}' --confirm
```

---

### `propose`: the ready-to-promote gate (SPEC-0194)

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
| `-bump major\|minor\|patch` | Auto-bump the `SKILL.md` version. **Parsed but not yet wired** in v1: it currently changes nothing. |

Exit: `0` gate passed · `1` generic / network error · `2` gate failed (one or more rows print `FAIL`). **`--dry-run` does
not force a `0`**: it skips the proposal POST, the verdict still rides the exit code. Measured,
because the earlier wording ("0 gate passed (or --dry-run)") said otherwise and a script that
believed it would treat every failed gate as a pass.

---

### `export-verification-kit`: portable, trust-nothing kit (SPEC-0276)

```bash
skillctl export-verification-kit --bundle <file.skb> --out <dir> [flags]
```

Builds a portable, offline verification kit that a third party can check with no network and
no trust in you.

**Prerequisite, and it is easy to miss:** the kit is built around the `BundleMeta` envelope
(`<name>.skbmeta.json`), which carries the author, registry and governance signatures and
comes into existence when the bundle is **admitted to a registry**. No verb produces it
locally, so a bundle that has only been packed and signed cannot be turned into a kit yet.
Fetch the envelope from the registry the bundle was admitted to, or pass it with `--meta`.
Offline, without it, the available check is `verify-sig` against the author key, which proves
authorship and nothing about governance, revocation or tenant scope (BUG-0215).

| Flag | Purpose |
|------|---------|
| `-bundle` | Signed `.skb` to package. **Required.** |
| `-out` | Output directory for the kit. **Required.** |
| `-meta` | BundleMeta envelope JSON (default: sidecar `.skbmeta.json`). |
| `-trust-roots` | Trust-roots YAML to source pinned keys from. Must be pinned mode. |
| `-revocations` | Optional signed revocation list to include (validated against the pinned key before inclusion). |
| `-registry` | Registry URL to disambiguate when trust-roots pins multiple. |
| `-zip` | Also produce `<out>.zip`. |

Exit: `0` the kit was written · `1` generic error · `2` usage / a missing required flag · plus
every code `verify.ExitCode` maps out of the §7 chain, which the kit refuses to package a
failing bundle past: `10`-`17` and `20`.

That is the whole space: 18 and 19 are raised by intent and awareness, not by the chain, and
22 and 23 come from the freshness and log-inclusion checks that `install` and `verify` run
around the chain and this verb does not.

```bash
skillctl export-verification-kit --bundle my-skill.skb --out ./kit --zip
```

---

### `compliance`: offline evidence aid (SPEC-0276)

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

### `login`: ER1 device pairing (FR-0043)

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

Both are also reachable as top-level flags:

| Flag | Purpose |
|------|---------|
| `-v`, `--version` | Aliases for `skillctl version`. |
| `-h`, `--help` | Aliases for `skillctl help`. |

Any command accepts `--help` (some sub-verbed groups print usage on the bare parent, e.g.
`skillctl agentid --help`, `skillctl translog`).

---

### The scanner family and the other commands

These commands are the SPEC-0189 inventory/report family plus a few operator utilities. They
share a common vocabulary: `--path` (repeatable) selects directories, `--recursive` walks
into them, `--include-home` adds `~/.claude/skills`, `--input` reads a saved scan JSON
instead of re-scanning, and `--out` writes to a file instead of stdout.

> `scan`, `report`, `diff`, `seal`, `import`, `menubar`, `review`, `browse`, `consolidate`
> and `sync-usage` do **not** implement `-h`/`--help`: run them with no arguments to see
> their own usage. Every other command accepts `--help`.

**`scan`**: scan skill directories and emit a JSON inventory.

| Flag | Purpose |
|------|---------|
| `--source claude\|user\|plugins\|all` | Scan source (SPEC-0189; default `claude`). Ignored when `--input` is given. |
| `--include-shadowed` | Also report skills shadowed by a higher-precedence copy. |
| `--with-trust` | Attach each entry's trust posture to the inventory. |
| `--path <dir>` | Legacy SPEC-0115 path selection. Repeatable; implies the `projects` source. |
| `--recursive` | Recurse into the given paths. |
| `--include-home` | Include the home skills dir. |
| `--format <fmt>` / `--output <fmt>` | Output format. |
| `--out <file>` | Write the inventory to a file. |
| `--verbose` | Verbose progress on stderr. |

`scan` can also admit what it finds in one step (SPEC-0189 §13), delegating to
`awareness sync`:

| Flag | Purpose |
|------|---------|
| `--push-to-registry` | Admit the scanned entries to the registry. Implies `--with-trust`. |
| `--dry-run-push` | Build the admission envelope and print the plan; do not POST. |
| `--registry <url>` | Registry to push to. |
| `--default-attest yellow\|green\|none` | Request a default attestation after admission (default `none`). |
| `--default-attest-yellow` | Shorthand for `--default-attest yellow`. |
| `--default-attest-green` | Shorthand for `--default-attest green`. |
| `--no-default-attest` | Shorthand for `--default-attest none`. |

**`scan --body [<skill-dir>]`**: a *different* command that happens to share the verb: the
SPEC-0246 §4.5 behavioural bodyscan over one skill's `SKILL.md` body. It is detected before
any inventory flag is parsed, so the two never interfere.

| Flag | Purpose |
|------|---------|
| `--body` | Route to the bodyscan. **Required** to select this mode. |
| `--format table\|json` / `--json` | Output format. |

Exit: `0` green · `1` scan / IO error · `2` any finding, or usage.

**`report`**: render a scan into a report.

| Flag | Purpose |
|------|---------|
| `--input <scan.json>` | The scan to render (a bare positional argument works too). |
| `--format html\|md` | Report format. |
| `--out <file>` | Write to a file instead of stdout. |

**`diff`**, diff two scans: `skillctl diff <scan1.json> <scan2.json>`.

| Flag | Purpose |
|------|---------|
| `--output json\|md\|html\|text` | Delta format. |
| `--out <file>` | Write to a file instead of stdout. |

**`review`**: serve a local review UI for a delta report.

| Flag | Purpose |
|------|---------|
| `--input <delta.json>` | The delta report to review. **Required.** |
| `--port <n>` | Listen port (default `9115`). |
| `--no-browser` | Do not open a browser. |

**`browse`**: build a local skill graph and serve an interactive browser at
`http://127.0.0.1:<port>/?token=…`.

| Flag | Purpose |
|------|---------|
| `--input <scan.json>` | Browse a saved scan instead of scanning now. |
| `--port <n>` | Listen port (default `9116`). |
| `--path <dir>` / `--recursive` / `--include-home` | What to scan when there is no `--input`. |
| `--no-browser` | Do not open a browser. |

**`consolidate`**: report duplicate / orphan / drifted / missing-frontmatter skills across
projects.

| Flag | Purpose |
|------|---------|
| `--input <scan.json>` / `--path <dir>` / `--recursive` / `--include-home` | What to analyse. |
| `--output text\|json\|md` | Report format (default `text`). |
| `--out <file>` | Write the report to a file. |
| `--report-only` | Report and stop: never offer to change anything. |
| `--fix` | After the report, **interactively** offer to fill frontmatter annotation gaps (asks `[y/N]`, and does nothing else). `--report-only` wins over it. |

**`seal`**: snapshot all installed skills into a signed inventory seal under
`~/.m3c-tools/skill-seals/`.

| Flag | Purpose |
|------|---------|
| `--input <scan.json>` / `--path <dir>` / `--include-home` | What to seal. |
| `--by <who>` | Who is sealing: recorded in the seal. |
| `--list` | List existing seals instead of creating one. |
| `--latest` | Show the most recent seal. |
| `--status` | Compare the current inventory against the latest seal. |

**`import`**: import a scan into a remote target.

| Flag | Purpose |
|------|---------|
| `--target <url>` | Target to import into. |
| `--api-key <key>` | API key for the target. |
| `--user-id <id>` | Attribute the imported inventory to this user id. |
| `--input <scan.json>` / `--path <dir>` / `--recursive` / `--include-home` | What to import. |
| `--dry-run` | Print what would be imported; do not POST. |

**`menubar`**: launch the macOS menu-bar skill monitor (interactive, long-running).

| Flag | Purpose |
|------|---------|
| `--path <dir>` | Directory to monitor. Repeatable; defaults to the current directory. |
| `--interval <dur>` | Re-scan interval as a Go duration (default `30m0s`). |
| `--include-home` | Also monitor the home skills dir. |

**`sync-usage`**: sync local skill-usage counters to ER1. Needs `--api-key`, `$M3C_API_KEY`,
or `~/.m3c-tools/er1_session.json`.

**`runbook publish <runbook.html>`**: publish an onboarding runbook into the THOH catalog
(SPEC-0272/0275).

| Flag | Purpose |
|------|---------|
| `--tag <tag>` | Release tag the runbook belongs to (e.g. `skillctl/v0.2.11-rc3`); the version is the last path segment. **Required.** |
| `--base <url>` | THOH catalog base URL (default `https://onboarding.guide`). |
| `--id <id>` | Runbook id in the catalog. |
| `--title <s>` | Catalog title. |
| `--purpose <s>` | One-line purpose. |
| `--goal <s>` | Completion goal. |
| `--dry-run` | Print the plan + descriptor; do not POST. |
| `--yes` | Skip the 🟡 confirm pause (scripted runs). |

**`room <share|unshare> [<skill>]`**: share/unshare a skill into a SPEC-0096 co-learning
room.

| Flag | Purpose |
|------|---------|
| `--room <label>` | Room label to map into/out of (e.g. `aims-basics`). **Required.** |
| `--skill <name>` | Skill to (un)map, or pass it as the positional argument. |
| `--digest sha256:<hex>` | Map only the bundle with this digest. |
| `--all` | Map every `m3c-skill-bundle` item in the context. |
| `--er1-context <ctx>` | ER1 context the bundles live in (default `skills`). |
| `--er1-target prod\|stage\|local` | ER1 target (default `prod`). |
| `--registry <spec>` | Registry spec; only `self` / `er1://…` are handled here. |
| `--dry-run` | Show what would change; do not POST. |
| `--yes` | Skip the confirm pause. |

---

## Roles & playbooks

Skill governance is a separation-of-duties system: no single role can both create and bless a
skill. Each role below lists *what you own* and the current `skillctl` commands you actually run.
For the HTTP-registry vs ER1-`self` split, see
[Trust roots & registries, which file, when](#trust-roots--registries--which-file-when); for
the exit codes every role branches on, see [Exit codes](#exit-codes).

### Author / Skill-Steward

You write the skill and put the first signature on it; you never bless your own governance
verdict. Keep your private key local: only the `.pub` ever leaves your machine.

```bash
skillctl keygen --out ~/.config/m3c/skill-keys/author            # -> author.priv + author.pub
skillctl pack --skill ~/.claude/skills/my-skill -o my-skill.skb \
  --name my-skill --version 1.0.0 --summary "…" \
  --data-scopes '{"id":"ds:fs/cwd","kind":"local_fs","access":"write","scope":"<cwd>/out/**","reason":"…"}'
skillctl sign --key ~/.config/m3c/skill-keys/author.priv my-skill.skb
skillctl verify-sig --pubkey ~/.config/m3c/skill-keys/author.pub my-skill.skb   # offline self-check
```

You may **not** attest your own skill (reviewer≠author is enforced. SPEC-0246) and `--author-intent`
is advisory only; imported bundles are capped at yellow.

### Reviewer

You own the binding governance verdict. Read the bundle, verify the author signature offline,
then post a signed attestation on the digest, as a *different* identity than the author.

```bash
skillctl verify --bundle my-skill.skb --trust-roots ./roots.yaml --json   # inspect offline, no install
skillctl attest sha256:<hex> --level green \
  --rationale "activation gate passed; intent matches data-scopes" \
  --reviewer-id id:reviewer@m3c --author-id id:author@m3c \
  --key ~/.config/m3c/skill-keys/reviewer.priv \
  --registry https://aims.example.com/api/skills
skillctl attest sha256:<hex> --level red --rationale "…" --reviewer-id id:reviewer@m3c --key …   # demote / retract
```

Passing `--author-id` triggers the offline reviewer≠author check. The most-recent qualified
attestation wins; a `red` re-attest is how a verdict is retracted.

### Registry Operator

You own the registry signing key and the trust distribution. In the ER1 `self` model *you are*
the registry: you admit and sign; in the HTTP model you run the server, hand out its pubkey,
register author identities, and drive the revocation feed.

```bash
# ER1 self: admit a bundle into your own context
skillctl publish my-skill --bundle my-skill.skb --version 1.0.0 \
  --registry self --er1-target prod --er1-context skills \
  --key ~/.config/m3c/skill-registry-self.priv --identity id:op@m3c
skillctl registry ls                                             # inspect the self registry
skillctl revoke sha256:<hex> --reason key_compromise --registry https://aims.example.com/api/skills
skillctl revoke feed --refresh --registry https://aims.example.com/api/skills   # roll the signed kill-switch HEAD
```

`--er1-context skills` is auto-prefixed to `<your-sub>___skills`; you can publish **only** into
your own context (403 / BUG-0165 otherwise). Registering an *author's* identity on an HTTP
registry is a server-side admin operation (see [Tenant operations](#tenant-operations)), not a
`skillctl` verb.

### Tenant Admin

You own the fleet's trust posture: which registry keys the machines pin, the `governance_minimum`
floor, and the tenant scope. That lives in the trust-roots file you distribute.

```bash
# HTTP fleet: pin the registry the whole tenant trusts (writes ~/.claude/skill-trust-roots.yaml)
skillctl trust add --registry https://aims.example.com/api/skills --pubkey registry.pub --id aims-prod
skillctl trust list
skillctl install my-skill@1.0.0 --tenant kup-berlin              # installs respect tenant scope + floor
```

Set `governance_minimum` (default green) in the distributed trust-roots file; a CISO-console
tenant block surfaces to consumers as exit `16`.

### CISO (Tenant Security Officer)

You authorize what runs inside your tenant and pull the trigger when something turns hostile.
The `skillctl`-side levers are revocation, the kill-switch feed, audit, and demotion.

```bash
skillctl revoke feed --status --registry https://aims.example.com/api/skills   # inspect the signed revocation HEAD
skillctl revoke sha256:<hex> --reason governance_retraction --actor-identity governance_reviewer --key reviewer.priv
skillctl audit --format json                                     # fleet inventory verdicts
```

A revoked digest fails install/verify with exit `17`; a stale revocation snapshot fails **closed**
with exit `22`.

### End-User / Consumer

You pin trust once, install verified skills, and let the runtime gate enforce the chain on every
invocation. You never publish.

```bash
# HTTP path: pin, install, verify
skillctl trust add --registry https://aims.example.com/api/skills --pubkey registry.pub --id aims-prod
skillctl install didactic-session@1.0.0 --tenant kup-berlin
skillctl verify didactic-session

# ER1 self path: hand-written ~/.claude/trust-roots.yaml (fingerprint checked out-of-band), then pull
skillctl pull --registry self --er1-target prod --er1-context <publisher-sub>___skills \
  --install --trust-mode --dry-run-install                       # G-23 step 1 (plan + token)
skillctl audit                                                   # OK | UNVERIFIED | BROKEN | BELOW_MIN
```

Wire the fail-closed gate so nothing runs unverified, it denies if it cannot verify:

```json
{ "hooks": { "PreToolUse": [ { "matcher": "Skill",
  "hooks": [ { "type": "command", "command": "skillctl verify-hook" } ] } ] } }
```

Don't hand-edit an installed skill under `~/.claude/skills/`: `skillctl audit` flags the drift
as `BROKEN`. See **[Acceptance & Handover: the skill lifecycle](../betrieb/acceptance-skillctl-lifecycle.md)**
for the two-person hand-off procedure over ER1.

---

## Tenant operations

Operator-side procedures. Each notes whether it applies to an **HTTP `/api/skills` registry** or
the **ER1 `self`** registry: they pin trust in different files (see
[Trust roots & registries](#trust-roots--registries--which-file-when)).

### Provision a tenant

**ER1 `self` (personal / small-team).** Nothing to stand up: your tenant *is* your ER1 login's
`<sub>___skills` context. Mint a registry key, publish into your own context, and hand consumers
the pubkey fingerprint out-of-band.

```bash
skillctl keygen --out ~/.config/m3c/skill-registry-self          # -> .priv + .pub
skillctl publish my-skill --bundle my-skill.skb --version 1.0.0 \
  --registry self --er1-target prod --er1-context skills \
  --key ~/.config/m3c/skill-registry-self.priv --identity id:op@m3c
# consumers hand-write ~/.claude/trust-roots.yaml (registry: self, pubkey_b64, fingerprint,
# governance_minimum) and pull from <your-sub>___skills: NOT `trust add`.
```

**HTTP `/api/skills` registry (fleet / regulated).** The server side (bucket, namespace,
per-tenant registry key) is provisioned by aims-core infrastructure, *not* by `skillctl`. Once
it exists, every consumer machine pins it and installs scoped to the tenant:

```bash
skillctl trust add --registry https://aims.example.com/api/skills --pubkey registry.pub --id aims-prod
skillctl install my-skill@1.0.0 --tenant <tenant-id>
```

### Rotate the registry key (overlap-publish window)

Never swap keys abruptly. Run an **overlap window** where both keys are accepted, re-sign under
the new key, then drop the old.

**HTTP registry**: `skill-trust-roots.yaml` holds multiple keys per registry, so pin the new key
alongside the old for the window:

```bash
skillctl keygen --out ~/.config/m3c/skill-registry-v2                       # 1) new keypair
skillctl trust add --registry https://aims.example.com/api/skills \
  --pubkey ~/.config/m3c/skill-registry-v2.pub --id aims-prod-v2            # 2) pin new (old still pinned)
# 3) re-admit / re-sign current bundles under the new key during the window
skillctl trust remove --registry https://aims.example.com/api/skills        # 4) after cutover, re-pin new-only
```

**ER1 `self`**: the flat `~/.claude/trust-roots.yaml` pins a single `pubkey_b64`, so re-publish
current bundles under the v2 key during the window, then have each consumer swap their
`pubkey_b64` / `fingerprint` (carried out-of-band) before you retire v1. Attestations bind to the
`bundle_digest`, not the signing key, so they generally survive a rotation.

### Register an author identity

**ER1 `self`.** Identity is the `id:you@m3c` you stamp into events plus the keypair behind it,
no self-serve endpoint. Generate the keypair, stamp `--identity` on publish (and `--identity-id`
on `sign`), and give consumers the `.pub` fingerprint out-of-band.

**HTTP registry.** Registering an author's public key is a **server-side admin operation** on the
aims-core registry (`POST /api/skills/identities` with an operator bearer token), not a
`skillctl` verb. The author sends their `.pub`; the operator registers it; consumers' `verify` /
`install` then check the author signature (exit `11` on mismatch) against that identity.

---

## `token`: the credential store for registries

Puts a registry token into the platform's protected store, shows what is
provisioned, and removes one. It is the write side of the credential resolution
that `pull`, `verify`, `install` and `attest` already read.

**The secret is read from STDIN and never from an argument.** An argument is
visible to every process on the machine through `ps` while the call runs, and it
lands in the shell history of whoever repeats the command by hand.

```bash
skillctl token set --backend gitlab --host git.example.de --read-only
# paste the token, then Ctrl-D. Or: echo "$TOK" | skillctl token set …
```

| Flag | Meaning |
|------|---------|
| `--backend <name>` | Which credential family: `gitlab`, `github` or `registry` (the HTTP registry). **Required** for `set` and `rm`. |
| `--host <host>` | The registry host, e.g. `git.example.de`. **Required.** A credential is stored per host so one machine can hold tokens for several instances. |
| `--read-only` | Store the **read** tier instead of the write tier. A pull prefers the read tier and only falls back to the write one, so an operator who provisions both never transmits a write token on a read. |

`token list --host <host>` prints, per backend and tier, **where** a credential
comes from, and never the credential. The source column is the interesting one:
an environment variable beats the protected store, so a stale export explains a
failure the stored token would not have caused.

`token rm` removes the local copy. That is **hygiene, not revocation**: the token
stays valid wherever it was issued until it is revoked there, which is the only
step that actually stops it.

| Platform | Protected store |
|---|---|
| macOS | Keychain (`security`), one generic-password item per service and host |
| Windows | DPAPI, ciphertext bound to the user account, under `%LOCALAPPDATA%\m3c\artifactauth` |
| Linux | none here. `set` refuses and names the environment variable instead of writing the token somewhere unprotected. |

The routine around all of this, including which token to ask GitLab for and why
a write token belongs to the project rather than to a person:
[Ops-Routine: Zugangstoken](../betrieb/ops-registry-tokens.de).

---

## Files & locations

| Path | Contents |
|------|----------|
| `~/.claude/skill-trust-roots.yaml` | Pinned **HTTP-registry** public keys (managed by `trust`). Read by `install` / `verify` / `audit`. |
| `~/.claude/trust-roots.yaml` | The **ER1 `self`** trust root (flat `registry: self` + `pubkey_b64`), hand-written / carried out-of-band. Read by `pull`. See [Trust roots & registries](#trust-roots--registries--which-file-when). |
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

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `skillctl version` prints `dev` | a stale binary earlier on `PATH` (e.g. `~/go/bin/skillctl` shadowing `~/.local/bin/skillctl`) | `which -a skillctl`; remove or rebuild the stale copy |
| `403 not authorized for this context` on `publish` | publishing into a context whose `<sub>` ≠ your login (BUG-0165) | publish only into your own `<sub>___skills` |
| `pull` rejects the trust-roots file | used `skill-trust-roots.yaml` (hosted) for the `self` path | use `~/.claude/trust-roots.yaml` (see [Trust roots & registries](#trust-roots--registries--which-file-when)) |
| `exit 12` (`registry_not_trusted`) | registry key not pinned | pin it, HTTP: `trust add`; self: fix `trust-roots.yaml` |
| `exit 13` (`governance_below_min`) | no attestation meets the floor | post a green attestation, or lower the floor deliberately |

---

## See also

- **[Quickstart: skillctl](../../old/quickstart-skillctl.md)**: the happy path in five minutes.
- **[Acceptance & Handover: the skill lifecycle](../betrieb/acceptance-skillctl-lifecycle.md)**: the two-person (Bob → Alice) acceptance procedure over ER1, with success criteria.
- **[Quickstart: the offline demo](../../old/quickstart-skillctl-demo.md)**: the `skillctl-demo` Kata walkthrough (CISO/booth).
- **[Manual: m3c-tools](manual-m3c-tools.md)**: the memory-capture toolkit `skillctl` ships alongside.
- **[Bug & feature tracking](../entwickler/bug-tracking.md)**: how a defect or a request is tracked across the private and public planes.
