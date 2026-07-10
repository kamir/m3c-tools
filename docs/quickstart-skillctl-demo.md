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
| `--mode guided\|kiosk\|kata` | `guided` (default): Enter advances each step; one pass, then it holds so the web mirror stays up. `kiosk`: timed auto-loop for a booth / screen-share. `kata`: hands-on training — the coach loop + Kata board (§5). Any unrecognised value is forced back to `guided`. |
| `--kiosk-delay <dur>` | Auto-advance delay in kiosk mode (default `3s`). |
| `--kata <K1..K5>` | Jump straight to one Kata (also forces `--mode kata`). |
| `--kata-list` | Print the 5-Kata board and exit (implies `--mode kata`). |
| `--port <n>` | Web-mirror port on `127.0.0.1` (default `8765`). |
| `--no-browser` | Do not auto-open the browser (print the URL only). |
| `--no-web` | CLI only; do not start the web mirror. |
| `--no-color` | Disable ANSI colour in the terminal. |
| `--skillctl <path>` | Path to the real `skillctl` binary. Default search: `./build/skillctl` → next to this binary → `$PATH`. |
| `--selftest` | Run the LIVE scenarios non-interactively and assert the real exit codes (see §4). |

```bash
./skillctl-demo --mode kiosk --kiosk-delay 5s      # booth loop
./skillctl-demo --mode kata                         # hands-on training (§5)
./skillctl-demo --kata K3                            # jump straight to Kata K3
./skillctl-demo --kata-list                         # print the 5-Kata board and exit
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
| **S3** — fleet kill-switch under live compromise | `PARTIAL` | `17 (revoked) / 22 (offline fail-closed)` | The **offline revocation deny is now demonstrable LIVE** — Kata **K5** runs `verify --bundle … --revocations <signed-list>` and a revoked digest returns a real `17`; a forged/untrusted list is fail-closed. The freshness contract (`--emergency`/`--checkpoint` → `22` on a stale snapshot + high-risk action) and FR-0045's signed-`RevocationHead` feed (`skillctl revoke feed`, HEAD-aware fetch) are merged. What stays roadmap here is **live fleet propagation** — the offline demo stands up no registry, so the fleet-wide kill event isn't executed live. Honest scope: this is a fail-closed kill-switch against **feed/transport compromise** (MITM, malicious mirror, set truncation, epoch rollback, replay, forged freshness — all defeated by the pinned registry key); it is **not** tamper-proof against a same-UID compromised process. |
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

## 5. Training mode (Kata) — **shipped**

> **Status: BUILT (`--mode kata`, `--kata K1..K5`, `--kata-list`).** The binary ships all three
> modes — `guided`, `kiosk`, and `kata`. Kata mode drives the real `skillctl` through five
> hands-on drills; **every beat is a real `skillctl` exit code**, never a simulated one.

Where the demo modes *sell* (a buyer watches containment happen), the **Kata** mode *onboards* —
it turns "watched a demo" into "can operate `skillctl`" through **deliberate practice with a
coach**, not a click-through. It reuses the CEW Kata vocabulary (SPEC-0303: the 3-state machine,
the **N/3 chip**, *sitzt* / *rust*) so tool-onboarding reinforces the same coaching model.
Nothing is self-reported — **a "pass" is a real exit code.**

```bash
./skillctl-demo --mode kata        # start the coach loop + Kata board
./skillctl-demo --kata K2          # jump straight to K2
./skillctl-demo --kata-list        # print the 5-Kata board and exit
```

**The five Katas** (target condition → practised with → green when):

| Kata | The learner can… | Practised with | Green when |
|------|------------------|----------------|-----------|
| **K1 Seal & prove** | seal a skill and prove authorship offline | `keygen → pack → sign → verify --bundle` → exit `0` | 3 distinct clean reps |
| **K2 Detect tamper** | catch a modified skill before it runs | edit on disk → `verify --all` → exit `10` | 3 reps |
| **K3 Govern reversibly** | run a destructive op that refuses to be forced | `audit --cleanup --dry-run-cleanup` → `--cleanup --confirm-delete` on a drifted set → exit `2` | 3 reps |
| **K4 Trust roots & install** | pin a registry and install only what's admitted | `trust add → install → verify` → exit `0` | 3 reps |
| **K5 Revoke & fail-closed** | deny a revoked skill offline, fail-closed | `verify --bundle … --revocations <signed-list>` → revoked digest → exit `17` | 3 reps (+ the S3 fleet-propagation roadmap panel to read) |

K5 is now a **live** beat: the offline revocation deny (`verify --bundle --revocations` → exit
`17`) runs for real. What remains roadmap is only **live fleet propagation** — the offline demo
stands up no registry (see the S3 panel in §3).

**The coach loop (the tool plays the coach — 5 questions per cycle):**

1. **Target** — the capability you should be able to demonstrate.
2. **Actual** — "Where are you now? Run it and observe." (the learner runs the real command)
3. **Obstacle** — "What blocked you?" (the tool maps the real exit code `10`/`2`/`17` to a
   plain-language obstacle).
4. **Next experiment + expectation** — the learner predicts the exit code, then acts.
5. **Go & see** — the learner runs it; the tool shows the **real** result and records a *beat*.

**Mastery.** A clean distinct rep is a beat toward **N/3 → *sitzt* (grün)**; a Kata *rusts*
(back toward rot) if unpractised past the stall window (`KATA_STALL_DAYS`, default `5`) —
identical to CEW's 3-state machine. Progress **persists locally** at
`~/.skillctl-demo/kata-progress.json`. The browser shows a **Kata board** — one card per Kata
with a rot/gelb/grün state and the N/3 chip — updating live as beats land.

---

## Next steps

- **Every `skillctl` command, flag and exit code:** [skillctl manual](manual-skillctl.md)
- **Author, sign and verify your own skill in five minutes:** [Quickstart: skillctl](quickstart-skillctl.md)
- **The scenarios' exit-code contracts** (`10` digest mismatch, `2` G-23 drift refusal, `17`
  revoked, `22` freshness fail-closed) are the [manual's exit-code table](manual-skillctl.md#exit-codes).
