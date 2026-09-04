---
layout: default
title: Quickstart: skillctl
---

# Quickstart: skillctl

Package, sign and verify your first agent skill in about five minutes: entirely offline,
no server required. Then see how the same bundle flows through admit → install → revoke.

> **What is skillctl?** The trust-and-governance CLI for agent skills. It gives every skill
> a verifiable identity and a full lifecycle, **author → pack → sign → admit → attest →
> verify / install → use → audit → revoke**, so nothing an agent runs is unauthorized or
> unprovable. The trust-chain check is **offline-verifiable**: no hosted CA sits in the
> verification path. For every command and flag, see the [skillctl manual](manual-skillctl.md).

---

## 1. Install

`skillctl` is a single CLI binary, attached to every
[release](https://github.com/kamir/m3c-tools/releases/latest). It runs identically on
macOS, Linux and Windows.

The **one-liner installers** fetch the right binary for your host, **verify cosign provenance
(GitHub OIDC) and the SHA-256 integrity digest**, then install to a **user-scoped** bin dir,
no admin rights required.

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/kamir/m3c-tools/f43eb496685a9f9cbc5b9a28046f568e70ee7dd9/tools/skillctl-install.ps1 | iex
```

Installs to `%LOCALAPPDATA%\Programs\skillctl` after verifying cosign provenance + SHA-256.
Override the target dir or the release with `$env:INSTALL_DIR` and `$env:RELEASE_BASE` before
running. This is the **light, user-scoped, no-admin** path: distinct from the machine-wide
`M3C-Tools-Setup.exe` installer; use **one or the other**, not both, so you don't end up with
two `skillctl.exe` on your `PATH`.

**macOS / Linux:**
```bash
curl -fsSL https://raw.githubusercontent.com/kamir/m3c-tools/f43eb496685a9f9cbc5b9a28046f568e70ee7dd9/tools/skillctl-install.sh | bash
```

Override the target dir or the release with `INSTALL_DIR=…` / `RELEASE_BASE=…`.

**Bootstrap integrity.** The one-liner URLs are pinned to the **immutable commit `f43eb49`**
(not the mutable `master` branch, where one rewrite could swap the bootstrap script *and* every
pin inside it). Verify the fetched bytes out-of-band before trusting them, expected SHA-256:
`tools/skillctl-install.ps1` → `9e8ceec9d2c87b4f5a7136653e8ca69224fa6579a55da221d9e2fe875f9924c8`;
`tools/skillctl-install.sh` → `adf9d768a376ee921f9df728546de072a2b3f14e9616e10bf3419fef520034a9`.
The [README Install section](../README.md#install) has a copy-paste verify-then-run recipe. On
each new signed release, bump the pinned commit **and** these hashes together.

**Manual install (signed release, raw binary):** the **only** skillctl distribution channel is
the signed `skillctl/v*` release (cosign/OIDC + SLSA provenance, plus a pinned ed25519 fallback).
The unsigned per-arch skillctl assets that used to ride along on the `v*` product release have
been **retired**: don't look for them there. To install by hand, pull the raw binary and its
`SHA256SUMS` from the signed release and verify integrity *before* moving it onto your `PATH`:
```bash
BASE="https://github.com/kamir/m3c-tools/releases/download/skillctl/v0.3.1"   # latest signed tag
curl -sLO "$BASE/skillctl-darwin-arm64"     # or darwin-amd64 / linux-amd64 / linux-arm64 / windows-amd64.exe
curl -sLO "$BASE/SHA256SUMS"
grep ' skillctl-darwin-arm64$' SHA256SUMS | shasum -a 256 -c -     # integrity gate. Fails closed on mismatch
sudo install skillctl-darwin-arm64 /usr/local/bin/skillctl
```

For full provenance verification (cosign bundle / ed25519 signature), prefer the one-liner
installers above. They do it for you, or build from source: `go build -o build/skillctl ./cmd/skillctl`.

```bash
skillctl version
skillctl help        # the full command map, grouped by capability
```

---

## 1b. Optional: prove it on your own machine (source self-test)

Before trusting a binary somebody else built, you can build it yourself and run the test
suite locally. One command per platform. It clones (or fast-forwards) the repository into
`~/m3c-tools`, checks the toolchain, verifies the module checksums, builds `skillctl`, runs
the skillctl test suite (with the race detector where a C toolchain is available), smoke-tests
the CLI, and prints a PASS/FAIL table.

**Windows (PowerShell):**
```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
irm https://raw.githubusercontent.com/kamir/m3c-tools/master/scripts/skillctl-test.ps1 | iex
```

**macOS / Linux:**
```bash
curl -fsSL https://raw.githubusercontent.com/kamir/m3c-tools/master/scripts/skillctl-test.sh | bash
```

Prerequisites: **git** and **Go 1.25+** on `PATH`. Nothing else. Missing either, or on a
fresh Windows box, see [Prerequisites](prerequisites.md): one `winget` line per tool, the
PATH reload that makes them visible in the session you already have open, and the
no-admin-rights path. The scripts never touch your trust roots, never write outside the
checkout, and exit non-zero if any step fails.

Prefer to read before you run? The scripts are
[`scripts/skillctl-test.ps1`](https://github.com/kamir/m3c-tools/blob/master/scripts/skillctl-test.ps1)
and [`scripts/skillctl-test.sh`](https://github.com/kamir/m3c-tools/blob/master/scripts/skillctl-test.sh).
Clone first, then run the local copy:

```bash
git clone https://github.com/kamir/m3c-tools.git && cd m3c-tools
./scripts/skillctl-test.sh --repo-dir "$PWD"
```

Useful flags, the same on both platforms:

| What | PowerShell | bash |
|---|---|---|
| Different checkout dir | `-RepoDir C:\src\m3c-tools` | `--repo-dir ~/src/m3c-tools` |
| Test another branch | `-Ref my-branch` | `--ref my-branch` |
| Whole module, not just skillctl | `-Full` | `--full` |
| Skip the race detector | `-NoRace` | `--no-race` |

Two things worth knowing. The default test scope is the package set the release gate uses
(`./cmd/skillctl/... ./pkg/skillctl/...`): a bare `go test ./...` also builds packages that
need the network, an ER1 server, whisper or a microphone, and their failures say nothing
about skillctl. And the race detector needs cgo plus a C compiler (mingw-w64 on Windows,
`xcode-select --install` on macOS, gcc on Linux); without one the tests still run and the
race line reports `SKIP` rather than quietly claiming a pass.

This is stage 1 by design: build reproducibility and the test suite. It is **not** the trust
and release gate. Lint, `govulncheck`, gosec, the coverage gate, the boundary gate and the
Windows e2e smoke run in [CI](https://github.com/kamir/m3c-tools/actions) and in
`make ci` / `make release-skillctl`; the Windows lifecycle proof is
[`scripts/skillctl-quickstart-windows.ps1`](https://github.com/kamir/m3c-tools/blob/master/scripts/skillctl-quickstart-windows.ps1),
described in [Windows release verification](releasing-skillctl-windows.md).

---

## 1c. Stage 2: run our CI on your own machine (enterprise gate)

When stage 1 is green, the next question is not "does it build" but **"would this tree pass
the gates we merge and release on?"** That is stage 2. It runs every CI gate that can honestly
run on a laptop, never fails fast, and ends with a PASS / FAIL / SKIP **trust report**.

**Windows (PowerShell):**
```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
irm https://raw.githubusercontent.com/kamir/m3c-tools/master/scripts/skillctl-enterprise-test.ps1 | iex
```

**macOS / Linux:**
```bash
curl -fsSL https://raw.githubusercontent.com/kamir/m3c-tools/master/scripts/skillctl-enterprise-test.sh | bash
```

| Gate | What it proves | CI counterpart |
|---|---|---|
| `stage1` | builds, tests pass, CLI answers | the section above |
| `vet` | no `go vet` finding | `ci.yml` Lint & Vet |
| `lint` | golangci-lint clean (pinned v2.13.2) | `ci.yml` Lint & Vet |
| `mod-tidy` | `go mod tidy` is a no-op | `ci.yml` CD-T4 |
| `docaudit` | every real CLI flag documented, every documented flag real | `ci.yml` docs-gate |
| `prose` | no U+2014 in the tracked tree | `ci.yml` prose-gate |
| `pins` | every pinned install one-liner resolves, digests match | `pin-guard` and BUG-0215 |
| `boundary` | the public/private plane boundary holds | `boundary-gate.yml` |
| `coverage` | the `.testcoverage.yml` ratchet over the trust surface | `coverage-gate.yml` |
| `govulncheck` | no CVE reachable from our code (pinned v1.7.0) | `ci.yml` govulncheck |
| `gosec` | no **new** SAST finding against the committed baseline | `gosec-diff-gate.yml` |
| `gitleaks` | no secret in the full history | `ci.yml` gitleaks |
| `trust-surface` | the whole trust surface, whole-package, no allow-list | `windows-gate.yml` |
| `lifecycle` | author, sign, verify, trust, and a tampered bundle **refused** | `skillctl-windows-smoke.yml` |

On Windows, three gates (`pins`, `boundary`, `gosec`) need a POSIX shell. Git for Windows
already ships one and this script finds it next to `git.exe`, even though the recommended
install leaves `bash.exe` off your PATH; [Prerequisites](prerequisites.md) explains that
trap, and why a `bash` that IS on your PATH is usually WSL and the wrong one.

Flags: `--full` / `-Full` widens the Go gates from the skillctl trust surface to `./...`,
`--no-install` / `-NoInstall` forbids installing a missing tool, `--strict` / `-Strict` makes a
skipped gate fail the run, `--skip-stage1` / `-SkipStage1` skips the build-and-test stage.

**Three things this report deliberately does not do.**

*It does not install tools behind your back without saying so.* golangci-lint, gosec and
go-test-coverage are fetched at the versions CI pins, into `$(go env GOPATH)/bin`, and the run
says so. gitleaks is never auto-installed: CI verifies its release tarball against a pinned
SHA-256 before running it, and a convenience script should not fake that. Missing tool, `SKIP`.

*It does not count a skip as a pass.* A gate that could not run says `SKIP` and the verdict
line reads `PASS with N skipped`. Use `--strict` when you want the report to be evidence.

*It is not the release.* SLSA provenance, cosign/OIDC signing, Code Scanning ingestion and the
cross-compile matrix exist only server-side. A green report here is not a substitute for a
green PR.

**One Windows detail worth knowing.** A shipping Windows build ignores `$HOME` for the
trust-root paths on purpose, because an environment variable is attacker-settable. The
hermetic trust tests inject `$HOME`, so on Windows they only run for real under
`-tags allow_home_override_test`. Stage 1 runs the untagged suite (shipping behaviour); the
`trust-surface` gate here runs the tagged one, and the `lifecycle` gate builds its sandbox
binary with that tag so the proof can never touch your real `%USERPROFILE%\.claude`. On macOS
and Linux no tag is needed: `$HOME` is honored there, and the lifecycle proof is
[`scripts/skillctl-quickstart-unix.sh`](https://github.com/kamir/m3c-tools/blob/master/scripts/skillctl-quickstart-unix.sh),
the twin of the Windows
[`scripts/skillctl-quickstart-windows.ps1`](https://github.com/kamir/m3c-tools/blob/master/scripts/skillctl-quickstart-windows.ps1).

---

## 1d. The human half: the Test Ride

Stages 1 and 2 prove the machine. They say nothing about whether **you** can operate the
tool. The ride does: about twenty minutes in which you seal a skill, pin a key, install it
as somebody else, and then break it four different ways and watch each attempt refused.

```bash
git clone https://github.com/kamir/m3c-tools.git
cd m3c-tools/demo/kup-training && ./run-all.sh --offline-only --no-pdf --no-release
```

On Windows, run the demo scripts with Git's bash: `& "$env:ProgramFiles\Git\bin\bash.exe"
run-all.sh --offline-only --no-pdf --no-release`, or from the Start menu's Git Bash. See
[Prerequisites](prerequisites.md).

The guide is [`demo/kup-training/TUTORIAL.md`](https://github.com/kamir/m3c-tools/blob/master/demo/kup-training/TUTORIAL.md):
what each step proves, what the exit codes mean, and the one lesson people get wrong (a valid
signature means "this is what that key sealed", never "this is safe"). Everything runs
offline under `demo/kup-training/artifacts/`, with a sandboxed fake home, so your real
`~/.claude/` is untouched; three further steps ride the online SCAN / USE / DECAY loop if you
have an ER1 account.

End it with evidence rather than a feeling:
`./run-and-prove.sh --skip-online --json ride-report.json`.

Then keep the muscle with [`skillctl-demo --mode kata`](quickstart-skillctl-demo.md#5-training-mode-kata-shipped),
five drills whose every beat is a real exit code.

---

## 2. Create your author identity

A skill is trusted because it's **signed**. Generate your ed25519 keypair once:

```bash
skillctl keygen --out ~/.config/m3c/skill-keys/mykey
```

This writes:

- `~/.config/m3c/skill-keys/mykey.priv`: your **private** key (mode `0600`, keep it secret)
- `~/.config/m3c/skill-keys/mykey.pub`: your **public** key (share this so others can verify)

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
| `--author-intent green\|yellow\|red` | Advisory governance hint (the verifier ignores it. Signed **attestations** are what bind) |
| `--data-scopes <json>` | Author-signed declared data-scope, bound into the bundle |

---

## 4. Sign it

```bash
skillctl sign --key ~/.config/m3c/skill-keys/mykey.priv my-skill.skb
```

This computes the bundle's SHA-256 digest, signs it with ed25519, and writes a **detached**
signature next to the bundle: `my-skill.skb.<digest>.author.sig`.

---

## 5. Verify it: offline

```bash
skillctl verify-sig --pubkey ~/.config/m3c/skill-keys/mykey.pub my-skill.skb
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
skillctl trust add --registry <url> --pubkey <registry.pub>   # pin a key (optional: --id <key-id>)
skillctl trust list                                           # show pinned registries
```

Then install: this pulls the bundle, runs the full trust-chain verifier, and installs
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
# As a PreToolUse(Skill) hook: reads the hook event on stdin, verifies the chain,
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
intents*, and it verifies offline, no authority in the path.

---

## Next steps

- **Every command, flag and exit code:** [skillctl manual](manual-skillctl.md)
- **Build it yourself and run the suite:** the [source self-test](#1b-optional-prove-it-on-your-own-machine-source-self-test) one-liners above
- **Run our CI on your own machine:** the [enterprise gate](#1c-stage-2-run-our-ci-on-your-own-machine-enterprise-gate) and its trust report
- **Prove you can operate it, not just that it builds:** the [Test Ride](#1d-the-human-half-the-test-ride)
- **Capture the memory your agents reason over:** [Quickstart: m3c-tools](quickstart-m3c-tools.md)
- **The full lifecycle & governance model** lives behind `skillctl help`: it groups commands
  by capability (signing, trust roots, install, agent identity, registry, transparency log,
  sessions, PLM project context).
