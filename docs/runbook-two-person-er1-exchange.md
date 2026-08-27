---
layout: default
title: "Runbook — two-person ER1 exchange (Mirko → Eric, prod)"
---

# Runbook — two-person ER1 exchange (Mirko → Eric)

Execute this together to stamp **SPEC-0246 AC1–AC4 green on prod ER1**: Mirko publishes a
signed, attested skill into his own ER1 context; Eric, a *different* ER1 login, trusts, pulls,
verifies, uses it — with **no write-back** to Mirko's registry. This is the one piece the
single-machine Windows smoke does not cover.

> Why this and not the automated harness: `demo/kup-training/` is single-machine. A true
> cross-principal exchange needs **two ER1 accounts**, so it's run by two people, once.
> Background + success criteria: [Acceptance & Handover](acceptance-skillctl-lifecycle.md).

---

## 0. Before you start (both)

| Both of you | Command / action |
|-------------|------------------|
| skillctl installed, real version | `skillctl version` → a real `skillctl/vX.Y.Z` (not `dev`) |
| Logged in to **prod** ER1 | `skillctl login --base-url https://onboarding.guide` then `skillctl login --status` |
| Agree a **room** label out-of-band | e.g. `aims-basics` — the co-learning room you share through |
| **Eric is a member of that room** | arranged in the **onboarding.guide console** (room membership is server-side; there is no `skillctl` join verb) |

Trust-roots file path used below (ER1 `self` path):
- macOS/Linux: `~/.claude/trust-roots.yaml`
- Windows: `%USERPROFILE%\.claude\trust-roots.yaml`

---

## Lane 1 — Mirko (author / publisher)

```bash
# M1. One-time: author keypair (keep .priv secret; only .pub leaves your machine).
skillctl keygen --out ~/.config/m3c/skill-registry-self          # -> .priv + .pub

# M2. Pack the skill (deterministic — pack twice, must be byte-identical).
skillctl pack --skill ~/.claude/skills/<name> -o <name>@<ver>.skb \
  --name <name> --version <ver> \
  --author-intent green --author-intent-rationale "what it does; no network; writes only ./out"

# M3. Sign, then self-check offline.
skillctl sign <name>@<ver>.skb --key ~/.config/m3c/skill-registry-self.priv --identity-id id:mirko@m3c
skillctl verify-sig <name>@<ver>.skb --pubkey ~/.config/m3c/skill-registry-self.pub   # -> exit 0

# M4. Publish (admit) into YOUR OWN context, shared into the agreed room.
#     --er1-context skills is auto-prefixed to <your-sub>___skills (you can only publish
#     into your own context — 403 / BUG-0165 otherwise).
skillctl publish <name>@<ver> --bundle <name>@<ver>.skb --registry self \
  --er1-target prod --er1-context skills \
  --key ~/.config/m3c/skill-registry-self.priv --identity id:mirko@m3c \
  --share-room <room> --yes

# M5. Post a GREEN attestation (governance). Reviewer ≠ author: use a distinct reviewer key
#     (a second human in production; for the exercise a separate key is fine). Without a green
#     attestation Eric's pull fails at the governance gate (exit 13).
skillctl keygen --out ~/.config/m3c/skill-reviewer                     # one-time reviewer key
skillctl publish --attest <name>@<ver> --level green \
  --rationale "reviewed; activation gate satisfied; intent matches data-scopes" \
  --registry self --er1-target prod --er1-context skills \
  --identity id:reviewer@m3c --key ~/.config/m3c/skill-reviewer.priv --yes
```

**Hand Eric, out-of-band (voice/Signal — never the same channel as the bundle):**

```bash
# (a) your context to read from:
echo "context: <your-sub>___skills"     # <your-sub> is the numeric prefix of your ER1 context
# (b) the base64 of your raw public key  -> goes into Eric's trust-roots.yaml `pubkey_b64`
openssl pkey -pubin -in ~/.config/m3c/skill-registry-self.pub -outform DER | tail -c 32 | base64
# (c) the fingerprint Eric reads back to you to confirm:
openssl pkey -pubin -in ~/.config/m3c/skill-registry-self.pub -outform DER | tail -c 32 | shasum -a 256
```

---

## Lane 2 — Eric (consumer)

```bash
# E1. Verify Mirko's fingerprint OUT-OF-BAND first, then pin his key by hand-writing the
#     self trust-roots file (the ER1 self path uses trust-roots.yaml, NOT `skillctl trust add`).
#     macOS/Linux: ~/.claude/trust-roots.yaml   Windows: %USERPROFILE%\.claude\trust-roots.yaml
cat > ~/.claude/trust-roots.yaml <<'YAML'
registry: self
pubkey_b64: <the base64 Mirko sent>
fingerprint: sha256:<the hex you verified out-of-band>
governance_minimum: green
YAML

# E2. G-23 step 1 — dry-run the install to review the plan + get a 5-minute token.
skillctl pull --registry self --er1-target prod --er1-context <mirko-sub>___skills \
  --skill <name> --install --trust-mode --dry-run-install --no-checkpoint
#   -> prints the create/overwrite plan + "dry-run-install token (5-minute TTL): <TOK>"

# --- review the plan, then confirm ---
# E3. G-23 step 2 — READ-ONLY consumer install (no --key, no --emit-installed → no write-back).
skillctl pull --registry self --er1-target prod --er1-context <mirko-sub>___skills \
  --skill <name> --install --trust-mode \
  --confirm-install --dry-run-install-token <TOK> --no-checkpoint
#   The 5 ER1 gates run: envelope-sig → not-revoked → governance-floor → digest → bundle-sigs.
#   Installs under ~/.claude/skills/<name>/ with a .m3c-provenance.json sidecar.

# E4. Re-verify + use + audit.
skillctl verify <name>                                   # -> exit 0
#   ...invoke the skill (through Claude Code or its entrypoint); confirm it produces its output...
skillctl audit --source all --minimum-governance green   # -> exit 0
```

---

## Pass criteria (tick together)

| AC | Check | Green when |
|----|-------|-----------|
| **AC1** | Mirko authored + published | M3 `verify-sig` → 0; M4 publish accepted (or "already published") |
| **AC2** | Reviewer (≠author) green attestation | M5 posted; Eric's pull passes the governance gate (no exit 13) |
| **AC3** | Different principal, read-only install, 5 gates, no write-back | E3 succeeds; E4 `verify` → 0; **nothing new appears in Mirko's registry** |
| **AC4** | The skill runs for Eric | E4 produces the skill's expected output |

All four green ⇒ the two-person ER1 exchange is validated on this release.

---

## Troubleshooting

| Symptom | Meaning | Fix |
|---------|---------|-----|
| publish `403 not authorized for this context` | you tried to publish into someone else's context (BUG-0165) | publish only into your **own** `--er1-context skills` (auto-prefixed to `<your-sub>___skills`) |
| Eric's pull returns nothing | Eric isn't a member of `<room>`, or wrong `--er1-context` | add Eric to the room in the onboarding.guide console; confirm `<mirko-sub>___skills` is exact |
| pull **exit 13** (`governance_below_min`) | no green attestation at/above the floor | Mirko posts the green attestation (M5) |
| pull **exit 12** (`registry_not_trusted`) | key mismatch / wrong `trust-roots.yaml` | re-check `pubkey_b64` + `fingerprint` against Mirko's key; ensure you edited `~/.claude/trust-roots.yaml` (not `skill-trust-roots.yaml`) |
| pull **exit 11 / 10** | signature / digest mismatch | the bundle or key doesn't match — do not proceed; re-fetch from Mirko |
| pull rejects the trust-roots file | wrong schema (used the hosted `skill-trust-roots.yaml`) | the self path uses the flat `~/.claude/trust-roots.yaml` |

---

## See also

- [Acceptance & Handover: the skill lifecycle](acceptance-skillctl-lifecycle.md) — the why + full success criteria (SPEC-0246 §10).
- [Manual: skillctl](manual-skillctl.md) — every command/flag; [Trust roots & registries](manual-skillctl.md#trust-roots--registries--which-file-when).
