---
layout: default
title: "Acceptance & Handover: the skillctl skill lifecycle (Mirko → Eric)"
---

# Acceptance & Handover — the skillctl skill lifecycle

**Audience:** Eric's team (a second organisation taking over `skillctl`).
**Goal:** validate the *full tool + skill lifecycle* end-to-end across **two people** —
Mirko authors, signs and publishes a skill; Eric trusts, pulls, verifies and uses it —
and prove that invalid skills are refused. Functionality and the skill lifecycle come
first; performance and scale are out of scope for this pass.

**Backend:** this procedure runs on the **ER1 `self` registry** (the field-proven path,
per **SPEC-0246** on the private maintenance plane).
The **only** two commands that are backend-specific are `publish` and `pull`; everything
else is identical when the registry is later swapped for the skill-repo backend
(see [§7 Backend swap point](#7-backend-swap-point-er1--skill-repo)).

> **Canonical reference:** every command below is documented in full in
> [manual-skillctl.md](manual-skillctl.md). This page is the *procedure*; the manual is the
> *reference*. Where they ever disagree, the manual wins.

---

## 1. The lifecycle at a glance

```
  MIRKO (author / supply)                 ERIC (consumer / demand)
  ─────────────────────────               ─────────────────────────
  keygen                                   (receive Mirko's public key
  pack        ─┐ trust core                 out-of-band + verify fingerprint)
  sign         │ (backend-agnostic)         trust root  ─┐ trust core
  verify-sig  ─┘                            pull         │ (5 gates)
  publish  ───┐ ER1 transport               verify      ─┘
  attest      │ (backend-SPECIFIC)          use the skill
  share-room ─┘                             audit
  …                                         …
  revoke (retire)  ← G-23 two-step
```

The trust decisions (and their exit codes) are pure functions of the bundle bytes + the
pinned key + the trust-roots file — the transport is invisible to them. Only `publish`
and `pull` know it is ER1.

---

## 2. Roles, machines, prerequisites

| Role | Who | Machine | Holds |
|------|-----|---------|-------|
| **Author / publisher** | Mirko | Machine A | author key `~/.config/m3c/skill-registry-self.priv`, ER1 login |
| **Consumer** | Eric | Machine B | Mirko's **public** key, ER1 login, a trust-roots file |
| **Reviewer** (governance) | a third identity | any | reviewer key; signs the green attestation |

Prerequisites on **both** machines (see [manual §Installation](manual-skillctl.md#installation)):

```bash
# Install skillctl (signed one-liner; verifies cosign provenance + SHA-256):
#   macOS/Linux:
curl -fsSL https://raw.githubusercontent.com/kamir/m3c-tools/ac04005305ee163790024520cda2d7aee1c2eed9/tools/skillctl-install.sh | bash
#   Windows (PowerShell):
#   irm https://raw.githubusercontent.com/kamir/m3c-tools/ac04005305ee163790024520cda2d7aee1c2eed9/tools/skillctl-install.ps1 | iex

skillctl version          # MUST print a real skillctl/vX.Y.Z — NOT "dev" (see Troubleshooting)
skillctl login --base-url https://onboarding.guide   # ER1 device pairing (FR-0043)
skillctl login --status
```

> **Bootstrap integrity.** The installer URLs are pinned to the **immutable commit `ac04005`**
> (not the mutable `master` branch — one rewrite there could swap the bootstrap script *and* every
> pin inside it). Verify the fetched bytes out-of-band — expected SHA-256:
> `tools/skillctl-install.ps1` → `9e8ceec9d2c87b4f5a7136653e8ca69224fa6579a55da221d9e2fe875f9924c8`,
> `tools/skillctl-install.sh` → `adf9d768a376ee921f9df728546de072a2b3f14e9616e10bf3419fef520034a9`.
> The [README Install section](../README.md#install) has a copy-paste verify-then-run recipe.

### The trust-root file — pick the right one (this is the #1 source of confusion)

| You are using… | Trust-roots file | How it's created | Read by |
|----------------|------------------|------------------|---------|
| **ER1 `self`** (this procedure) | `~/.claude/trust-roots.yaml` | **hand-written / carried out-of-band** (flat: `registry: self`, `pubkey_b64`, `fingerprint`, `governance_minimum`) | `pull` (default) |
| HTTP `/api/skills` registry | `~/.claude/skill-trust-roots.yaml` | `skillctl trust add --registry <URL> --pubkey <path>` | `install`, `verify` |

For this ER1 procedure, Eric uses **`~/.claude/trust-roots.yaml`** and does **not** run
`skillctl trust add` (that is the HTTP-registry path). Do not mix the two files.

---

## Quick validate on Windows (PowerShell)

To confirm skillctl's lifecycle works on a fresh **Windows** box — the trust core, with no ER1
and no second person needed — copy this into **Windows PowerShell** (grab it from the repo, or
straight from here):

```powershell
# 1) Install skillctl (verifies cosign provenance + SHA-256, no admin):
irm https://raw.githubusercontent.com/kamir/m3c-tools/ac04005305ee163790024520cda2d7aee1c2eed9/tools/skillctl-install.ps1 | iex

# 2) Download + run the lifecycle smoke (keygen -> pack -> sign -> verify -> trust -> tamper):
$q = "$env:TEMP\skillctl-quickstart.ps1"
irm https://raw.githubusercontent.com/kamir/m3c-tools/ac04005305ee163790024520cda2d7aee1c2eed9/scripts/skillctl-quickstart-windows.ps1 -OutFile $q
powershell -ExecutionPolicy Bypass -File $q
```

> **Pinned + verifiable.** Both URLs above are pinned to the **immutable commit `ac04005`**.
> Expected SHA-256: `tools/skillctl-install.ps1` → `9e8ceec9d2c87b4f5a7136653e8ca69224fa6579a55da221d9e2fe875f9924c8`;
> `scripts/skillctl-quickstart-windows.ps1` → `74b8ca8dbc7b6cae932bb9c1e016628aaac9c678db3ac7cb9159204dc5d7e27c`.
> Verify the fetched bytes (`Get-FileHash <file> -Algorithm SHA256`) before running.

It walks **keygen → pack → sign → verify-sig → trust add → tamper** in a throwaway `%TEMP%` dir
and prints one PASS/FAIL line per step, exiting non-zero if any required step fails. The tamper
case must be **refused** (exit 11) — that is the fail-closed proof. It writes nothing outside
`%TEMP%` and touches neither ER1 nor your real `~/.claude`. (This is the same script the
`installer-winps51` / quickstart-smoke CI job runs on `windows-latest`.)

**What this does *not* cover:** the two-person ER1 exchange in Parts A/B below — that needs two
ER1 logins over prod and is run manually. This smoke validates the **tool + trust core** on Windows.

---

## 3. Part A — Mirko's lane (author → publish over ER1 `self`)

```bash
# A1. One-time: generate the author keypair.
skillctl keygen --out ~/.config/m3c/skill-registry-self
#   → ~/.config/m3c/skill-registry-self.priv (0600) + .pub (0644)
#   Keep .priv secret. .pub is what Eric will pin.

# A2. Pack the skill directory into a sealed .skb bundle (deterministic).
skillctl pack --skill ~/.claude/skills/<name> -o <name>@<ver>.skb \
              --name <name> --version <ver> \
              --author-intent green \
              --author-intent-rationale "Writes one local file. No network. No subprocess."
#   Determinism check (acceptance): pack a second time and diff — MUST be byte-identical.

# A3. Sign the bundle (detached ed25519 author signature over the digest).
skillctl sign --key ~/.config/m3c/skill-registry-self.priv --identity-id id:mirko@m3c <name>@<ver>.skb
#   → sidecar <bundle>.<hex>.author.sig ; prints digest sha256:<hex>

# A4. Local self-check BEFORE publishing.
skillctl verify-sig --pubkey ~/.config/m3c/skill-registry-self.pub <name>@<ver>.skb
#   → EXIT 0 expected.

# --- HUMAN CHECKPOINT: admit (publishing to the registry) ---
# A5. Publish (admit) into your own ER1 context, sharing it into a co-learning room.
skillctl publish <name>@<ver> --bundle <name>@<ver>.skb --registry self \
              --er1-target prod --er1-context skills \
              --key ~/.config/m3c/skill-registry-self.priv --identity id:mirko@m3c \
              --share-room aims-basics
#   NOTE: --er1-context skills is auto-prefixed to <your-sub>___skills (BUG-0165).
#   Re-publishing the same digest is an idempotent no-op.

# --- HUMAN CHECKPOINT: attest (signing a governance verdict) ---
# A6. Post the reviewer's green attestation (reviewer ≠ author; SPEC-0246 §5).
skillctl publish --attest <name>@<ver> --level green \
              --rationale "Reviewed; activation gate satisfied." \
              --registry self --er1-target prod --er1-context skills \
              --identity id:reviewer@m3c --key ~/.config/m3c/reviewer.priv
```

**Hand-off to Eric (out-of-band).** Give Eric (a) your **public** key `skill-registry-self.pub`,
(b) your ER1 **context** `<your-sub>___skills`, and (c) the **fingerprint** so he can verify it
by voice/Signal (never trust a key that arrived over the same channel as the bundle):

```bash
# fingerprint of your raw ed25519 public key:
openssl pkey -pubin -in ~/.config/m3c/skill-registry-self.pub -outform DER | tail -c 32 | shasum -a 256
# base64 of the same raw key (goes into Eric's trust-roots.yaml → pubkey_b64):
openssl pkey -pubin -in ~/.config/m3c/skill-registry-self.pub -outform DER | tail -c 32 | base64
```

---

## 4. Part B — Eric's lane (consumer: trust → pull → verify → use over ER1 `self`)

```bash
# B1. Verify the fingerprint OUT-OF-BAND first (SPEC-0246 R6.3) — read it back to Mirko.

# B2. Hand-write the self trust-roots file (NOT `trust add`).
cat > ~/.claude/trust-roots.yaml <<'YAML'
registry: self
pubkey_b64: <base64 of Mirko's raw ed25519 public key>
fingerprint: sha256:<hex you verified out-of-band>
governance_minimum: green
YAML

# B3. G-23 step 1 — dry-run the install to review the plan + get a 5-min token.
skillctl pull --registry self --er1-target prod --er1-context <mirko-sub>___skills \
              --dry-run-install
#   Reads ~/.claude/trust-roots.yaml by default. Prints the create/overwrite plan + token.

# --- HUMAN CHECKPOINT: review the plan, then confirm ---
# B4. G-23 step 2 — read-only consumer install (no --key, no --emit-installed).
skillctl pull --registry self --er1-target prod --er1-context <mirko-sub>___skills \
              --install --trust-mode \
              --confirm-install --dry-run-install-token <tok> --no-checkpoint
#   The 5 ER1 gates run: envelope-sig → not-revoked → governance-floor → digest → bundle-sigs.
#   Installs under ~/.claude/skills/<name>/ with a .m3c-provenance.json sidecar.
#   Read-only ⇒ NO write-back to Mirko's registry (SPEC-0246 R6.4).

# B5. Re-verify the installed skill.
skillctl verify <name>          # → EXIT 0 expected

# B6. USE the skill (the load-bearing proof it actually works for Eric).
#   Invoke the skill through Claude Code / run its entrypoint; confirm it produces its output.

# B7. Antivirus-style audit of everything installed.
skillctl audit --source all --minimum-governance green --format table   # → EXIT 0 expected
```

---

## 5. Part C — Negative acceptance (invalid skills MUST be refused)

Fail-closed is the whole point. Each case has a **specific** expected exit code (the full
table is in [manual §Exit codes](manual-skillctl.md#exit-codes)):

| # | Attack | Command | Expect |
|---|--------|---------|--------|
| N1 | Tampered bundle (flip a byte) | `skillctl verify-sig --pubkey mirko.pub tampered.skb` | **exit 11** (author_sig_invalid) |
| N2 | Wrong key / impersonation | `skillctl verify-sig --pubkey mirko.pub attacker.skb` | **exit 11** (control vs attacker.pub = 0) |
| N3 | No signature | `skillctl verify-sig --pubkey mirko.pub no-sig.skb` | **non-zero** (11 or 1 — never 0) |
| N4 | Digest mismatch | installed bundle modified after signing | **exit 10** |
| N5 | Registry not trusted / forged root | pull with an unpinned registry key | **exit 12** |
| N6 | Governance below minimum | pull a skill with no green attestation | **exit 13** |
| N7 | **Revoked author/bundle** | `skillctl verify <name> --revocations <signed-list>` | **exit 17** (SPEC-0198) |

**Coverage today (honest):** N1–N3 are automated in `demo/kup-training/` (steps 06/07/08).
N4–N7 are **not** in that harness — N7 (revoke) lives in the separate CISO Kata demo
(`skillctl-demo --kata K5`), and N4/N5/N6 are asserted by unit tests, not the two-person
script. Closing N4–N7 in the acceptance harness is a tracked gap (see §8).

---

## 6. Success criteria (the pass bar)

Cross-person acceptance is defined by **SPEC-0246 §10 (AC1–AC5)**. A handover run **PASSES** iff:

| AC | Criterion | Evidence / expected result |
|----|-----------|----------------------------|
| **AC1** | Author can pack+sign+publish into their own ER1 context | A2–A5 succeed; `verify-sig` → 0; publish returns admitted/already-admitted |
| **AC2** | Reviewer (≠ author) attestation is required and honoured | A6 green attestation present; governance floor `green` enforced |
| **AC3** | **A *different principal* (Eric) completes a read-only consumer install end-to-end, all 5 gates pass, no write-back** | B3–B5: `pull --install --trust-mode` (no `--key`, no `--emit-installed`) → skill under `~/.claude/skills/<name>/`; `verify` → 0; Mirko's registry unchanged |
| **AC4** | The installed skill actually runs for Eric | B6 produces the skill's expected output |
| **AC5** | Invalid skills are refused with the correct exit code | Part C: N1–N3 (min bar) refuse; N4–N7 as coverage lands |

**Minimum pass bar for the first handover:** AC1–AC4 green **and** N1–N3 refuse. AC5's
full matrix (N4–N7) is the target as the harness converges (§8). Field status: the Eric
consumer path was proven live on **2026-06-09** (SPEC-0246 §11).

---

## 7. Backend swap point (ER1 → skill-repo)

Only the **transport** changes when ER1 is replaced by the skill-repo backend. This is the
seam `IsER1Registry` already draws in code, and the invariant SPEC-0248 §4 asserts.

| Stays **identical** (trust core) | Changes (transport only) |
|----------------------------------|--------------------------|
| `keygen`, `pack`, `sign`, `verify-sig` | `publish` mechanics (`POST /upload_2`) |
| `attest`, `trust`, the trust-roots file | `pull` mechanics (`GET /memory/<ctx>`) |
| `install` (G-23, provenance, `~/.claude/skills/`) | the `<sub>___skills` context convention |
| The **verification gauntlet + exit codes (0/10–17)** | the `m3c-skill-bundle` tag schema + inline `.skb` |
| `audit` (0/2/3), `revoke` (G-23) | `--registry` / `--er1-target` / `--er1-context` / `--share-room` flags |
| | room-based read authorization (SPEC-0096) |

> The skill-repo backend is **not yet a written spec** — today it is the architectural
> decision in SPEC-0188 §8 **D3** plus the `IsER1Registry` seam. A named `Backend` interface
> (and a real SPEC — 0356 is unallocated) is the planned formalisation. When it lands, this
> procedure is edited in exactly one place: Parts A5 and B3–B4 (the `publish`/`pull` flags).

---

## 8. Relationship to the automated harness — and the convergence plan

The `demo/kup-training/` scripts are the **automated regression** for the trust core:

- **What they prove today:** the offline cryptographic chain (keygen→pack→sign→verify),
  the Mirko→Eric transfer (G3 → `artifacts/eric-home/output/hello.txt`), and the negative
  tests N1–N3 (G4) — driven by `run-and-prove.sh` (exit 0 iff every check passes, `--json`
  summary) and `run-all.sh` (the four release gates G1–G4).
- **The divergence:** that harness uses the older **HTTP `/api/skills/*` admission registry**,
  not the **ER1 `self`** path this procedure (and Eric, in the field) use. So it proves the
  trust core, but not the ER1 transport of AC3.
- **Convergence plan (tracked):**
  1. **Done (best-effort):** `02-mirko-publish.sh` / `05-eric-install-and-run.sh` now attempt
     the ER1 `self` transport (`publish` / `pull --registry self`, target `local` by default) as
     a **single-machine smoke** — the runner's ER1 login acts as the author. It needs a live
     local ER1 to actually exercise, and a true two-person cross-principal AC3 run needs two ER1
     accounts (validated manually, §11). The offline chain + N1–N3 remain the automated bar.
  2. Add negative steps for **N4 (exit 10)**, **N5 (12)**, **N6 (13)**, **N7 (17)** (pull N7
     in from the Kata harness).
  3. Wire (or explicitly scope out) the orphaned demand-side steps `10-scan` / `11-use` /
     `12-decay` (not run by either driver today; `12`'s decay path is unimplemented).
  4. Remove the Mac-only assumptions (macOS keychain for credentials, `pandoc`+`xelatex`
     for the PDF gate, `shasum` naming, hard-coded source paths) so Eric's team can run it
     on Linux/Windows.

Until convergence, the acceptance bar for the ER1 transport (AC3) is met by **running Part
B manually** and recording the result; the harness covers the trust core and negatives.

---

## 9. Handover checklist for Eric's team

- [ ] `skillctl` installed on both machines; `skillctl version` prints a real tag (not `dev`).
- [ ] ER1 login works on both (`skillctl login --status`), against the correct `--base-url`.
- [ ] Mirko's public key received **and fingerprint verified out-of-band**.
- [ ] `~/.claude/trust-roots.yaml` written on Eric's box (self format), `governance_minimum: green`.
- [ ] Part A (author) completes: `verify-sig` → 0, publish admitted, green attestation posted.
- [ ] Part B (consumer) completes: `pull --install --trust-mode` → 0 gates, `verify` → 0, skill runs, `audit` → 0.
- [ ] Part C: N1–N3 refuse with the expected exit codes.
- [ ] No write-back appears in Mirko's registry (AC3/R6.4).
- [ ] Result recorded (a `run-and-prove.sh --json` file, or the checklist above signed off).

---

## 10. Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `skillctl version` prints `dev` | a stale binary earlier on `PATH` (e.g. `~/go/bin/skillctl` shadowing `~/.local/bin/skillctl`) | remove/rebuild the stale one; `which -a skillctl` to find shadows |
| `403 not authorized for this context` on publish | publishing into a context whose `<sub>` ≠ your Google login (BUG-0165) | publish only into **your own** `<your-sub>___skills`; Eric *reads* Mirko's context |
| `pull` rejects the trust-roots file | wrong file/schema — used `skill-trust-roots.yaml` (hosted) for the self path | use `~/.claude/trust-roots.yaml` (flat self format); see §2 table |
| install one-liner 404s | targeting a release that isn't published yet | check the release is published; or set `RELEASE_BASE` to a published tag |
| `exit 12` on install | registry key not pinned | pin it (HTTP path: `trust add`; self path: fix `trust-roots.yaml`) |
| `exit 13` | no attestation meets the `green` floor | author must post a green attestation (A6), or lower the floor deliberately |

---

## See also

- [Runbook — two-person ER1 exchange (Mirko → Eric)](runbook-two-person-er1-exchange.md) — the copy-paste prod runbook to actually execute Parts A/B together.
- [manual-skillctl.md](manual-skillctl.md) — the full command/flag/exit-code reference.
- [quickstart-skillctl.md](quickstart-skillctl.md) — the author happy-path in 5 minutes.
- [quickstart-skillctl-demo.md](quickstart-skillctl-demo.md) — the offline Kata demo.
- SPEC-0246 (cross-person exchange, AC1–AC5), SPEC-0248 (lifecycle umbrella), SPEC-0188 (trust chain + exit codes).
