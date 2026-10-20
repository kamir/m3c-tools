---
layout: default
title: "Tutorial: Katas and Test Ride, practice instead of watching"
---

# Tutorial: Katas and Test Ride

[Deutsch](tutorial-katas-und-test-ride.de.md) · [English](tutorial-katas-und-test-ride.en.md)

**Audience:** You have installed `skillctl` and want to **operate it**, beyond reading
about it. Or you are teaching a course and need a sequence that produces evidence.

**What you will have:** A guided run in which you seal a skill, pin somebody else's key,
install as another person and then break the skill in four different ways, with every
attempt refused. Afterwards, five exercises to repeat until the operations become familiar.

**The central point:** In both formats, a pass means **a real exit code**, never self-reporting.

---

## The map: four stages, two kinds of evidence

Two different questions are repeatedly confused.

| Stage | Question | Artifact | Proves |
|---|---|---|---|
| 1 | Does it build, and do the tests run? | `scripts/skillctl-test.sh` or `.ps1` | The machine |
| 2 | Would this revision pass our CI gates? | `scripts/skillctl-enterprise-test.sh` or `.ps1` | The machine |
| 3 | Can **I** operate the tool? | `demo/kup-training/`, the **Test Ride** | The person, once |
| 3b | Can I operate the **publisher chain**? | `scripts/tutorial-smoke.sh --walk` | The person, using the chain from scenario 02 |
| 4 | Will I still be able to do it next week? | `skillctl-demo --mode kata`, the **Katas** | The person, over time |

Stages 1 and 2 are in the [quickstart](quickstart-skillctl.md#1b-optional-prove-it-on-your-own-machine-source-self-test).
This tutorial covers 3 and 4. The order reflects a dependency: the ride uses what stage 1 built.

---

## Part 1: the Test Ride (about 20 minutes, offline)

### 1.1 Get it and start

```bash
git clone https://github.com/kamir/m3c-tools.git
cd m3c-tools/demo/kup-training
./run-all.sh --offline-only --no-pdf --no-release
```

The three flags mean no server, no PDF typesetting and no cross-platform release build.
What remains proves the trust chain and works without a network.

**Everything stays in this directory.** The ride writes only under
`demo/kup-training/artifacts/`, using `artifacts/alice-home/` as a fake `$HOME`.
Your real `~/.claude/` is untouched. Cleanup is `rm -rf artifacts/`.

### 1.2 What happens

Ten steps, in this order:

| Step | Role | Demonstration | Expected result |
|---|---|---|---|
| `00` | Tool | Builds `skillctl` from source and checks the environment | Binary exists |
| `01` | Bob, author | `keygen`, `pack`, `sign`, `verify-sig`; packing twice produces identical bytes | Exit `0`, determinism demonstrated |
| `02` | Bob | Identity and bundle enter the registry, online only | Cleanly skipped offline |
| `03` | Reviewer | `green` attestation on the digest | Verdict exists |
| `04` | Alice | Pins Bob's key in her own trust roots | Key is in the file |
| `05` | Alice | Verifies, installs and **runs the skill** | `output/hello.txt` is created |
| `06` | Attacker | Changes one byte in the bundle and renames the signature accordingly | Exit **`11`**, invalid signature |
| `07` | Attacker | Different key and signature, claiming Bob's identity | Exit **`11`** against Bob's pin, `0` against the attacker's own |
| `08` | Attacker | Bundle without any signature | Refusal, no bypass |
| `09` | Attacker | Edits an installed file afterwards | Drift detected, repaired from the bundle |

Step `07` teaches the most: the same bundle is checked against two different keys and
receives two different verdicts. What decides is **whose key you pinned**.

### 1.3 The lesson people often misunderstand

A valid signature says **"This is what this key sealed."** It never says "This is safe."
Step `07` proves that: the attacker's signature is mathematically valid, but it does
not belong to the person you trust.

### 1.4 Finish with evidence

```bash
./run-and-prove.sh --skip-online --chain-only --json ride-report.json
```

This is the companion to `run-all.sh`: it checks both the exit codes and whether every
step actually created its essential artifact, then writes a summary. `--chain-only`
omits the two gates that need a handbook source or a release build. Without it,
the run stops after all trust checks have already passed.

`ride-report.json` is your evidence. Keep it together with `skillctl version`.

### 1.5 The online half (optional)

Three further steps connect the chain to usage. `run-all.sh` does **not** execute them;
they require reachable aims-core and `ER1_API_KEY`:

```bash
./10-scan-and-sync.sh     # SCAN:  was ist installiert, ins Profil spiegeln
./11-use-skill.sh         # USE:   Nutzungsereignisse, Reifegrad steigt
./12-decay.sh             # DECAY: ungeübtes verfällt wieder
```

Each checks reachability first and skips with a warning if the server or key is missing.
`10-scan-and-sync.sh --operator` reads the trainer's **real** `~/.claude/skills/` rather
than the demo home. Use it deliberately.

### 1.6 Troubleshooting

| Symptom | Cause | Remedy |
|---|---|---|
| Step `01` fails at `sign`, "insecure mode 0644" | Private key permissions are too broad | `chmod 600 artifacts/keys/*.priv`, then restart. Since 2026-09-04, `00-preflight.sh` enforces this automatically. |
| The run ends red after all trust checks passed | A gate needs a source available only on the maintenance plane | `run-and-prove.sh --skip-online --chain-only` |
| Steps `02`, `03` say "skipped" | No registry is reachable | Expected and acceptable: the cryptographic proof is the same offline. |

---

## Part 1b: guided publisher chain (about 10 minutes, offline)

The Test Ride above demonstrates the trust chain from author and consumer perspectives.
To practice **publishing itself**, admitting, attesting, pulling and the two refusal cases,
use the companion script for [scenario 02](tutorial-szenario-02-erster-signierter-skill.en.md):

```bash
make build-skillctl
./scripts/tutorial-smoke.sh --walk      # geführt, mit Pausen und Begründung
./scripts/tutorial-smoke.sh             # dieselbe Kette, ohne Pausen, als Prüfung
```

Ten steps in a disposable sandbox, without a network or server, against a bare `local://`
registry. Steps 9 and 10 matter most: a valid attestation is not accepted because the
consumer has not pinned the reviewer; a renamed signature is rejected with exit `11`.

Without `--walk`, the same script is a blocking part of `scripts/check-docs.sh`.
It serves as both exercise and gate, so the tutorials cannot silently become outdated.

---

## Part 2: the Katas (five exercises, ongoing)

The ride proves once that you can do it. Katas maintain that ability through deliberate
practice with a coach, and the tool itself is the coach.

### 2.1 Start

```bash
# aus dem Repository, baut skillctl gleich mit:
make build-skillctl-demo

./build/skillctl-demo --kata-list        # das Brett anzeigen und beenden
./build/skillctl-demo --mode kata        # die Coach-Schleife starten
./build/skillctl-demo --kata K3          # direkt in eine Übung springen
```

On startup, the tool builds an isolated sandbox with its own `HOME`, keys, file-based
registry and trust roots, finds the real `skillctl`, opens a browser mirror at
`127.0.0.1` and shows the Kata board. Offline, without installation or admin rights.

### 2.2 The five exercises

| Kata | Afterwards you can | Practiced with | Green when |
|---|---|---|---|
| **K1 Seal & prove** | Seal a skill and prove authorship offline | `keygen`, `pack`, `sign`, `verify --bundle` | Three clean runs with exit `0` |
| **K2 Detect tamper** | Detect tampering **before** the skill loads | Edit a file on disk, `verify --all --quarantine` | Three runs with verdict `10` |
| **K3 Govern reversibly** | Perform a destructive operation that cannot be forced | `audit --cleanup --dry-run-cleanup`, then confirm after state changes | Three runs with exit `2` |
| **K4 Trust roots & install** | Pin a registry and install only admitted content | `trust add`, `verify --bundle` | Three runs with exit `0` |
| **K5 Revoke & fail-closed** | Reject a revoked skill offline | `verify --bundle … --revocations <signierte Liste>` | One run with exit `17` |

K3 is easily underestimated: there is **no** `--force`. The plan receives a token valid
for five minutes; confirmation checks the state **again**. If it has changed, confirmation
refuses. This protects against your own late-night mistakes rather than attackers.

### 2.3 How a round works

Five questions, the same every round:

1. **Target.** What should you demonstrate?
2. **Actual state.** Where are you? Run it and observe.
3. **Obstacle.** What blocked you? The tool translates real exit codes `10`, `2`, `17`
   into a plain-language obstacle.
4. **Next experiment and expectation.** **Predict the exit code** before acting.
5. **Go and see.** Execute, compare the actual result; one beat is counted.

Step 4 is the core. Predicting the exit code means you have a model; merely executing
collects anecdotes.

### 2.4 Mastery and decay

Three states, as in CEW: **red** for new, **yellow** for practicing, **green** for mastered.
A clean, independent run counts as one beat; `N/3` leads to green. An unpracticed Kata
**rusts** backwards after the interval set by `KATA_STALL_DAYS`, default `5`.

Progress is stored locally in `~/.skillctl-demo/kata-progress.json`. The browser shows
the same state live on a board, one card per Kata.

Clicking through five Katas in one afternoon therefore gives **not** green but five
instances of `1/3`. This is intentional.

### 2.5 For CI and checking that results are real

```bash
./build/skillctl-demo --selftest
```

Runs the live scenarios without interaction, compares every observed exit code against
its expectation, prints a PASS/FAIL table and exits non-zero when an assertion fails.

The tool follows its own rule: scenarios that **execute nothing** are marked `ROADMAP`
or `PARTIAL` and never presented as real verdicts. In K5, offline revocation with
exit `17` is real. Fleet-wide propagation remains conceptual because this setup starts
no registry.

---

## Part 3: for trainers

A cohort afternoon that leaves evidence:

1. **Beforehand, individually, 30 minutes.** Everyone runs stages 1 and 2
   ([Quickstart §1b/§1c](quickstart-skillctl.md#1b-optional-prove-it-on-your-own-machine-source-self-test)).
   Problems here concern the toolchain rather than the lesson.
2. **Together, 30 minutes.** Test Ride through step `05`. Pause there and have participants
   show that the file was created.
3. **Together, 30 minutes.** Steps `06` through `09`, one at a time, each preceded by
   "Which exit code do you expect?"
4. **Finish, 10 minutes.** Everyone runs `run-and-prove.sh --skip-online --chain-only --json`;
   collect their reports.
5. **Afterwards, over two weeks.** Practice each Kata three times across different days.
   The board is the progress report.

For presentations without audience interaction, `--mode kiosk --kiosk-delay 5s` loops
continuously for a booth or shared screen.

A note on materials: `make-pdf.sh` builds three PDFs using a private maintenance-plane
source. Without that source, keep `--no-pdf`; this does not change the ride.

---

## Which format to use

| Situation | Choose |
|---|---|
| New to the tool, wants to see everything once | Offline Test Ride |
| Needs to operate it for a customer tomorrow | Test Ride, then K1 and K4 |
| Last used it two months ago | `--kata-list`, then practice whatever turned red |
| Must demonstrate that the chain holds | `run-and-prove.sh … --json` plus `skillctl-demo --selftest` |
| Wants to show a decision-maker five minutes | Default `skillctl-demo`, scenarios S1 and S5 |

---

## Where to go next

- Own skills on several machines: [scenario 01](tutorial-szenario-01-eigene-skills-mehrere-maschinen.en.md)
- First signed skill reviewed by another person: [scenario 02](tutorial-szenario-02-erster-signierter-skill.en.md)
- All demo modes, flags and scenarios: [Quickstart skillctl-demo](quickstart-skillctl-demo.md)
- Every command, flag and exit code: [manual](../referenz/manual-skillctl.md)
