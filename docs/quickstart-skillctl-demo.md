---
layout: default
title: Quickstart — skillctl-demo
---

# Quickstart: skillctl-demo

Show a CISO the trust plane **containing a live attack** — a poisoned bundle refused with
exit `10`, a governance action that refuses to be forced with exit `2` — in about five
minutes, on a locked-down, **offline** laptop. No install, no admin, no server.

> **What is skillctl-demo?** One self-contained, offline binary that **bundles the real
> `skillctl`** and drives it through real trust scenarios in a hermetic sandbox. Every LIVE
> verdict you see is a **real `skillctl` exit code** — nothing is simulated. A browser opens
> to a live mirror (scenario graphics + a streaming terminal); the CLI runs the same deck.
> For every underlying command and flag, see the [skillctl manual](manual-skillctl.md).

> **Honesty rule (non-negotiable).** LIVE scenarios run the real `skillctl` and show its real
> exit code. ROADMAP / PARTIAL panels **run nothing** and are labelled as such — the demo
> never dresses a simulated output as a real verdict.

---

## 1. Run it

The demo ships as a zip with two files: `skillctl-demo` and `skillctl` (plus embedded web
assets). It is **offline, no admin, no install** — double-click or run it, and a browser
opens.

```bash
./skillctl-demo
```

On launch it builds a hermetic sandbox (a throwaway `HOME` with its own keys, sample skills,
a file-based registry and pinned trust-roots), locates the real `skillctl`, starts a web
mirror on `127.0.0.1`, and opens your browser. It prints the sandbox `HOME`, the resolved
`skillctl` path, and the mirror URL.

### Flags

| Flag | Purpose |
|------|---------|
| `--mode guided\|kiosk` | `guided` (default): Enter advances each step; one pass, then it holds so the web mirror stays up. `kiosk`: timed auto-loop for a booth / screen-share. **These are the only two modes** — any other value is forced back to `guided`. |
| `--kiosk-delay <dur>` | Auto-advance delay in kiosk mode (default `3s`). |
| `--port <n>` | Web-mirror port on `127.0.0.1` (default `8765`). |
| `--no-browser` | Do not auto-open the browser (print the URL only). |
| `--no-web` | CLI only; do not start the web mirror. |
| `--no-color` | Disable ANSI colour in the terminal. |
| `--skillctl <path>` | Path to the real `skillctl` binary. Default search: `./build/skillctl` → next to this binary → `$PATH`. |
| `--selftest` | Run the LIVE scenarios non-interactively and assert the real exit codes (see §4). |

```bash
./skillctl-demo --mode kiosk --kiosk-delay 5s      # booth loop
./skillctl-demo --no-browser --port 9000           # headless / custom port
./skillctl-demo --skillctl /usr/local/bin/skillctl # point at a specific skillctl
```

---

## 2. The LIVE scenarios (real exit codes)

These three run the real `skillctl` in the sandbox. Watch the exit-code badge flip.

### S1 — Poisoned script → the signature prevents the run

A signed `.skb` skill bundle is verified **offline** against a pinned key. An attacker edits a
script *inside* the bundle to exfiltrate `~/.ssh` and reships it — one changed byte breaks the
signed digest.

```
verify --bundle  →  0 (clean)  →  10 (digest mismatch, refused)
```

The signature does not *describe* the risk — it **prevents the run**. Nothing is written to
`~/.claude/skills/`.

### S2A — Post-install tamper → re-verify catches it

An installed, green skill is edited on disk to smuggle a prompt-injection into `SKILL.md`. The
load-time `PreToolUse(Skill)` gate re-runs the trust chain **before** Claude Code can load it,
then a sweep quarantines it.

```
verify-hook  →  0 (allow)  →  2 (gate BLOCKS the tampered load)
verify --all →  per-skill verdict 10 (digest mismatch)  →  quarantined
```

### S5 — Reversible governance / no-force (drift refuses)

`skillctl`'s own destructive op — a cache cleanup — is a **G-23 two-step**: a signed dry-run
plan with a short-lived token, then a confirm that **re-checks the live affected-set**. When
the set drifts before you confirm, the confirm **refuses**.

```
audit --cleanup --dry-run-cleanup   →  0 (plan + signed 5-minute token)
audit --cleanup --confirm-delete …  →  2 (confirm REFUSES on drift)
```

Exit `2` is a usage / precondition refusal — the token no longer matches the live set. **There
is no `--force`**; both the plan and the refusal are auditable.

---

## 3. The roadmap panels (nothing is run)

The deck also shows three scenarios the demo does **not** run — each renders its story and the
*closest built surface*, honestly labelled. They are never presented as live verdicts.

| Scenario | Tier | Documented exit | Why it isn't run here |
|----------|------|-----------------|-----------------------|
| **S2BC** — runtime envelope violation + fleet kill | `ROADMAP` | `envelope 32 · revoke 17` | The Go-native OS-level egress cage is FR-0044 (pending); the block point exists only as a Python reference (`pkg/skillgate`, SPEC-0202). Exit `32` is shown as roadmap — no `skillctl` subcommand emits it today. |
| **S3** — fleet kill-switch under live compromise | `PARTIAL` | `17 (revoked) / 22 (offline fail-closed)` | The **offline freshness contract IS built** — `verify --bundle --revocations/--emergency` returns `17` (revoked) and `22` (stale + high-risk, fail-closed), proven by SPEC-0279 tests. The signed-HEAD fleet-propagation endpoint (FR-0045) is the remaining work, and this offline demo stands up no registry — so S3 is shown as a built surface, not run live. |
| **S4** — untrusted internet import → airlock | `ROADMAP` | `1 (refused on critical-rule hit)` | A static import scanner exists (`import_public_cmds.go`, SPEC-0201), but the airlock flow isn't wired for the offline demo — so S4 stays a labelled roadmap panel. |

---

## 4. Prove it in CI — `--selftest`

`--selftest` runs the three LIVE scenarios non-interactively, asserts each observed exit code
against its expectation, prints a PASS/FAIL table, and exits non-zero if any assertion fails —
the CI-friendly proof that the honest core actually blocks.

```bash
./skillctl-demo --selftest
```

```
──────── selftest summary ────────
  1. allowed  exit=0  expected=0   [PASS]
  2. blocked  exit=10 expected=10  [PASS]
  ...
  ✔ all N exit-code assertions passed (real skillctl).
```

---

## 5. Training mode (Kata) — **planned**, not shipped

> **Status: PLANNED (P4 in `DEMO-TOOL-design.md`).** The binary today accepts **only** `--mode
> guided` and `--mode kiosk`; there is no Kata flag, code path, or scenario in the shipped
> tool. The section below describes the *designed* onboarding mode — treat it as a preview,
> not a runnable command.

Where the demo modes *sell* (a buyer watches containment happen), the designed **Kata** mode
*onboards* — it turns "watched a demo" into "can operate `skillctl`" through **deliberate
practice with a coach**, not a click-through. It reuses the CEW Kata vocabulary (SPEC-0303:
the 3-state machine, the **N/3 chip**, *sitzt* / *rust*) so tool-onboarding reinforces the
same coaching model. Nothing is self-reported — **a "pass" is a real exit code.**

**The five planned Katas** (target condition → practised with → green when):

| Kata | The learner can… | Practised with | Green when |
|------|------------------|----------------|-----------|
| **K1 Seal & prove** | seal a skill and prove authorship offline | `keygen → pack → sign → verify --bundle` | 3 distinct clean reps |
| **K2 Detect tamper** | catch a modified skill before it runs | edit on disk → `verify --all` → exit `10` | 3 reps |
| **K3 Govern reversibly** | run a destructive op that refuses to be forced | `audit --cleanup --dry-run-cleanup` → `--cleanup --confirm-delete` on a drifted set → exit `2` | 3 reps |
| **K4 Trust roots & install** | pin a registry and install only what's admitted | `trust add → install → verify` | 3 reps |
| **K5 Revoke & fail-closed** *(concept + roadmap)* | reason about fleet revocation & offline deny | `revoke` live + the S3 roadmap panel | 1 rep + read |

**The coach loop (the tool plays the coach — 5 questions per cycle):**

1. **Target** — the capability you should be able to demonstrate.
2. **Actual** — "Where are you now? Run it and observe." (the learner runs the real command)
3. **Obstacle** — "What blocked you?" (the tool maps the real exit code `10`/`11`/`12`/`2` to a
   plain-language obstacle).
4. **Next experiment + expectation** — the learner predicts the exit code, then acts.
5. **Go & see** — the learner runs it; the tool shows the **real** result and records a *beat*.

**Mastery.** A clean distinct rep is a beat toward **N/3 → *sitzt* (green)**; a Kata *rusts* if
unpractised past a stall window (identical to CEW's 3-state machine). Progress would persist
locally (`~/.skillctl-demo/kata-progress.json`), with a later bridge to `cew_kata_events`
(SPEC-0303) and the `skillprofile` aware→practiced→fluent ladder (SPEC-0121). The browser would
show a **Kata board** — one card per Kata with a rot/gelb/grün state and the N/3 chip.

Again: this is the **design** (P4). Today, run `--mode guided` or `--mode kiosk`.

---

## Next steps

- **Every `skillctl` command, flag and exit code:** [skillctl manual](manual-skillctl.md)
- **Author, sign and verify your own skill in five minutes:** [Quickstart: skillctl](quickstart-skillctl.md)
- **The scenarios' exit-code contracts** (`10` digest mismatch, `2` G-23 drift refusal, `17`
  revoked, `22` freshness fail-closed) are the [manual's exit-code table](manual-skillctl.md#exit-codes).
