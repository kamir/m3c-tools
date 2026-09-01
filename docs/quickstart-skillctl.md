---
layout: default
title: Quickstart — skillctl
---

# Quickstart: skillctl

Package, sign and verify your first agent skill in about five minutes — entirely offline,
no server required. Then see how the same bundle flows through admit → install → revoke.

> **What is skillctl?** The trust-and-governance CLI for agent skills. It gives every skill
> a verifiable identity and a full lifecycle — **author → pack → sign → admit → attest →
> verify / install → use → audit → revoke** — so nothing an agent runs is unauthorized or
> unprovable. The trust-chain check is **offline-verifiable**: no hosted CA sits in the
> verification path. For every command and flag, see the [skillctl manual](manual-skillctl.md).

---

## 1. Install

`skillctl` is a single CLI binary, attached to every
[release](https://github.com/kamir/m3c-tools/releases/latest). It runs identically on
macOS, Linux and Windows.

**macOS (Apple Silicon):**
```bash
curl -sL https://github.com/kamir/m3c-tools/releases/latest/download/skillctl-darwin-arm64.tar.gz | tar xz \
  && sudo mv skillctl-darwin-arm64 /usr/local/bin/skillctl
```

Swap `darwin-arm64` for `darwin-amd64`, `linux-amd64`, `linux-arm64`, or use the
`skillctl-windows-amd64.zip`. Or build from source: `go build -o build/skillctl ./cmd/skillctl`.

```bash
skillctl version
skillctl help        # the full command map, grouped by capability
```

---

## 2. Create your author identity

A skill is trusted because it's **signed**. Generate your ed25519 keypair once:

```bash
skillctl keygen --out ~/.config/m3c/skill-keys/mykey
```

This writes:

- `~/.config/m3c/skill-keys/mykey.priv` — your **private** key (mode `0600`, keep it secret)
- `~/.config/m3c/skill-keys/mykey.pub` — your **public** key (share this so others can verify)

Both are PEM-wrapped ed25519 (PKCS#8 / SPKI).

---

## 3. Pack a skill into a sealed bundle

A skill directory just needs a `SKILL.md`. Package it into a `.skb` bundle with a manifest:

```bash
skillctl pack \
  --skill ./my-skill \
  -o my-skill.skb \
  --name my-skill \
  --version 1.0.0 \
  --summary "What this skill does"
```

Useful optional manifest fields:

| Flag | Purpose |
|------|---------|
| `--source-repo` / `--source-commit` / `--source-path` | Provenance: where the skill came from |
| `--depends-on kind:name:constraint` | Declare dependencies, e.g. `python:requests:>=2.31` (repeatable) |
| `--author-intent green\|yellow\|red` | Advisory governance hint (the verifier ignores it — signed **attestations** are what bind) |
| `--data-scopes <json>` | Author-signed declared data-scope, bound into the bundle |

---

## 4. Sign it

```bash
skillctl sign my-skill.skb --key ~/.config/m3c/skill-keys/mykey.priv
```

This computes the bundle's SHA-256 digest, signs it with ed25519, and writes a **detached**
signature next to the bundle: `my-skill.skb.<digest>.author.sig`.

---

## 5. Verify it — offline

```bash
skillctl verify-sig my-skill.skb --pubkey ~/.config/m3c/skill-keys/mykey.pub
```

It recomputes the digest, finds the matching signature, and checks it. **No network, no CA.**

```
Exit codes:  0 ok  ·  11 signature invalid  ·  1 other error  ·  2 usage
```

That's the core loop: **anyone with your public key can prove a bundle is authentic and
unmodified, with nothing but the two files in front of them.**

---

## 6. Trust a registry, then install

To pull and install skills from a registry, first **pin** that registry's public key in your
trust roots (`~/.claude/skill-trust-roots.yaml`):

```bash
skillctl trust add   <registry> --pubkey <registry.pub>   # pin a key
skillctl trust list                                        # show pinned registries
```

Then install — this pulls the bundle, runs the full trust-chain verifier, and installs
atomically under `~/.claude/skills/<name>/`, refusing if **any** step fails:

```bash
skillctl install my-skill@1.0.0        # or a digest pin: my-skill@sha256:<hex>
skillctl verify  my-skill              # re-run the trust check on an installed skill
skillctl verify  --all                 # re-verify everything (catches new revocations)
```

The verifier returns **numbered exit codes** so automation can branch precisely:

| Code | Meaning | Code | Meaning |
|-----:|---------|-----:|---------|
| `0` | ok | `13` | governance below minimum |
| `10` | digest mismatch | `14` | `depends_on` unsatisfied |
| `11` | author signature invalid | `15` | blob missing |
| `12` | registry not in trust roots | `16` | tenant blocked (CISO verdict) |

---

## 7. Publish, attest, revoke (the governed path)

Once you run your own registry (via ER1), the lifecycle extends:

```bash
skillctl login                                     # device-pair against ER1 (browser)
skillctl publish my-skill --bundle my-skill.skb    # admit the bundle to your `self` registry
skillctl publish --attest my-skill --level green --rationale "reviewed"   # governance attestation
skillctl pull                                      # run the 5-gate gauntlet; stage verified bundles
skillctl registry ls                               # list admitted bundles
skillctl publish --revoke my-skill --digest sha256:… --reason "superseded"   # revoke on demand
skillctl audit  <name>                             # inspect a skill's trust timeline
```

Revocation is **signed and offline-verifiable**, with freshness contracts (fail-closed) so a
stale or rolled-back revocation list is rejected rather than silently trusted.

---

## 8. Wire the Claude Code trust gate (optional, powerful)

`skillctl` can gate every skill invocation in Claude Code, failing **closed**:

```bash
# As a PreToolUse(Skill) hook — reads the hook event on stdin, verifies the chain,
# and emits allow/deny. Wire it in settings, don't run it by hand:
skillctl verify-hook

skillctl gate-stats --since 168h        # decisions, top blocks, cache-hit rate
```

Now an agent literally cannot invoke a skill that isn't authorized and provable.

---

## Bonus: give an agent a provable identity

```bash
skillctl agentid issue  --owner <you> --owner-key mykey.priv \
                        --for-agent <agent-id> --skills my-skill --intents summarize
skillctl agentid verify --bundle agent.mandate --offline    # verify offline against pinned keys
skillctl agentid show   --bundle agent.mandate              # owner, grant, expiry, fingerprints
```

An **AgentID** is an owner-signed mandate that says *this agent may use these skills for these
intents* — and it verifies offline, no authority in the path.

---

## Next steps

- **Every command, flag and exit code:** [skillctl manual](manual-skillctl.md)
- **Capture the memory your agents reason over:** [Quickstart: m3c-tools](quickstart-m3c-tools.md)
- **The full lifecycle & governance model** lives behind `skillctl help` — it groups commands
  by capability (signing, trust roots, install, agent identity, registry, transparency log,
  sessions, PLM project context).
