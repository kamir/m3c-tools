# The Test Ride: prove the skill trust chain with your own hands

**Who this is for:** anyone who will publish, review, install or run agent skills with
`skillctl`. No prior knowledge of the tool. You will not read about trust; you will break
a bundle and watch the tool refuse it.

**How long:** about 20 minutes offline, plus 10 minutes if you also ride the online half.

**What this is not:** it is not the technical acceptance test. That one asks whether the
MACHINE is sound (build, tests, CI gates), and it is a one-liner:

```bash
curl -fsSL https://raw.githubusercontent.com/kamir/m3c-tools/master/scripts/skillctl-test.sh | bash             # stage 1: builds + tests
curl -fsSL https://raw.githubusercontent.com/kamir/m3c-tools/master/scripts/skillctl-enterprise-test.sh | bash  # stage 2: the CI gates
```

On Windows the same two scripts exist as `.ps1`; see
[Quickstart: skillctl](../../docs/quickstart-skillctl.md#1b-optional-prove-it-on-your-own-machine-source-self-test).
Run those first. When they are green, the machine is fine and the remaining question is
whether **you** can operate the thing. That is this ride.

---

## Before you start

| You need | Why | Check |
|---|---|---|
| `git`, Go 1.25+ | the demo builds `skillctl` from this checkout | `go version` |
| `bash`, `curl`, `tar`, `shasum` | the step scripts | present on macOS and Linux |
| about 200 MB free | build cache and artifacts | n/a |
| **only for the online half** | an ER1 account, `ER1_API_KEY`, and a reachable aims-core | see [Part 3](#part-3-the-online-half-scan-use-decay) |

```bash
git clone https://github.com/kamir/m3c-tools.git
cd m3c-tools/demo/kup-training
```

Everything this ride writes lands under `demo/kup-training/artifacts/`, which is
git-ignored. Your real `~/.claude/` is never touched: the demo gives "Eric" a fake home at
`artifacts/eric-home/`. When you are done, `rm -rf artifacts/` and nothing remains.

---

## Part 1: the honest path (about 10 minutes)

Run the offline chain end to end:

```bash
./run-all.sh --offline-only --no-pdf --no-release
```

It prints one block per step. Read them as you go; this is the ride, not a build.

| Step | What happens | What it proves |
|---|---|---|
| `00` preflight | builds `skillctl` from this checkout into `artifacts/bin/` | you are testing the code in front of you |
| `01` Mirko authors | `keygen`, `pack`, `sign`, `verify-sig` | a skill becomes a sealed bundle with a detached signature. Note the line **"determinism: two packs of the same input are byte-identical"**: the seal is over content, not over a moment in time |
| `02` Mirko publishes | offline: skipped cleanly | the registry is storage, not the source of trust |
| `03` reviewer attests | writes `attestation.json`, level green | a second person's verdict is a separate artifact from the author's signature |
| `04` Eric pins trust | `trust add` writes `artifacts/eric-home/.claude/skill-trust-roots.yaml` | trust is a decision Eric makes locally, about a key, in a file he owns |
| `05` Eric installs and runs | verify, extract, run | `artifacts/eric-home/output/hello.txt` exists **only** if the whole chain held |

Look at that last file. It is the point of the exercise:

```bash
cat artifacts/eric-home/output/hello.txt
```

A file that could not have appeared if any link had been broken. Now break some links.

---

## Part 2: the four refusals

Steps `06` to `09` each hand `skillctl` an invalid skill and assert the refusal. `run-all.sh`
already ran them; run one by hand and read the output slowly:

```bash
./06-invalid-tampered.sh
```

| Step | The attack | The refusal |
|---|---|---|
| `06` | one byte of the bundle is flipped, the original signature kept | exit **11**, signature invalid |
| `07` | an attacker signs their own bundle and claims Mirko's identity | exit **11** against Mirko's pinned key, exit 0 against the attacker's own key. The signature is fine; the IDENTITY is not |
| `08` | the bundle arrives with no signature at all | non-zero refusal, never a fail-open |
| `09` | an installed file is edited after installation | the `CHECKSUMS` comparison catches it, and repair restores from the signed bundle |

**The thing to take away from `07`.** It is the one people get wrong. A valid signature does
not mean "safe". It means "this is exactly what the holder of that key sealed". Everything
else is your decision about the key, and that decision is step `04`.

**Exit codes are the vocabulary.** `0` accepted, `10` digest mismatch, `11` author signature
invalid, `17` revoked, `2` a governance action refusing to be forced. The full table is in
the [skillctl manual](../../docs/manual-skillctl.md#exit-codes).

---

## Part 3: the online half (SCAN, USE, DECAY)

Parts 1 and 2 prove the SUPPLY side and need no server. Steps `10` to `12` close the loop on
the DEMAND side: what is installed, who uses it, and what fades when nobody does. They are
**not** part of `run-all.sh`; run them by hand, and they need a live aims-core.

```bash
export ER1_API_KEY=...                          # or store it once in the macOS keychain:
                                                #   security add-generic-password -s aims-core-er1 -a "$USER" -w
export REGISTRY_URL=https://127.0.0.1:8081      # default; point it at your instance
```

Each step checks reachability first (`GET $REGISTRY_URL/api/skills/health` must answer 200)
and **skips itself with a warning** if the server or the key is missing, so running them
without a server is safe, it just proves nothing.

| Step | What happens | What it proves |
|---|---|---|
| `10-scan-and-sync.sh` | scans Eric's installed skills and imports them into his skill profile | the fleet view is derived from what is actually on disk, not from what someone claimed |
| `11-use-skill.sh` | posts five usage events for `kup-hello` | mastery is earned by use, and every use is a recorded event |
| `12-decay.sh` | recalculates mastery for every profile | an unused skill decays; a capability nobody exercises is not a capability |

`10` also has an `--operator` mode that scans your REAL `~/.claude/skills/` instead of the
demo home. Read the script before you use it: it is the one command in this ride that leaves
the sandbox.

---

## What you just proved

1. A skill can be sealed so that any later change is detectable (`01`, `06`).
2. The seal names a key, not a person, and pinning that key is a local decision (`04`, `07`).
3. A second pair of eyes is a separate, verifiable artifact (`03`).
4. Nothing runs on Eric's machine that did not survive the whole chain (`05`).
5. Refusal is the default; there is no path where an invalid bundle is quietly accepted
   (`06` to `09`).
6. What a team can actually do is measured from installed reality and real usage, and it
   decays without practice (`10` to `12`).

## Leave evidence, not a feeling

Do not report "I did the training". Produce the artifact:

```bash
./run-and-prove.sh --skip-online --json ride-report.json
```

`run-and-prove.sh` runs the same chain and asserts every step's load-bearing output, not just
its exit code. The JSON summary names the host, the steps, and what each produced. Attach it
to your onboarding ticket; keep the trust-claim rule that governs this tool pointed at
yourself too: a claim is worth what its evidence is worth.

## Then keep the muscle

One ride teaches the shape. It does not make you fluent, and steps `06` to `09` were run FOR
you here. The practice mode drives the same commands as five drills you repeat until they
sit, and every beat is a real exit code:

```bash
skillctl-demo --mode kata      # K1 seal, K2 tamper, K3 govern, K4 trust roots, K5 revoke
skillctl-demo --kata-list      # the board, and your progress
```

See [Quickstart: skillctl-demo](../../docs/quickstart-skillctl-demo.md#5-training-mode-kata-shipped).

---

## If something goes wrong

| Symptom | Cause | Fix |
|---|---|---|
| `private key ... has insecure mode 0644` | a key file arrived with the wrong permissions | `chmod 600 artifacts/keys/*.priv`. Preflight now does this for you; if you see it, say so, it means a key came from somewhere it should not have |
| step `01` fails and `05`, `06`, `09` follow it down | there is no signature, so nothing downstream can verify | fix `01` first, the rest are consequences, not four separate bugs |
| `online mode not available: skipping` | no `ER1_API_KEY`, or the registry did not answer 200 | see [Part 3](#part-3-the-online-half-scan-use-decay). Parts 1 and 2 do not need it |
| `make-pdf.sh` cannot find the manual | it renders a document from the private maintenance checkout | set `M3C_MAINTENANCE_DIR`, or skip it with `--no-pdf`. It is a maintainer gate, not part of the ride |
| you want to start over | | `rm -rf artifacts/` and run again. Keys are regenerated |

## Where the rest of it lives

- Every command, flag and exit code: [skillctl manual](../../docs/manual-skillctl.md)
- Install, author, sign, verify in five minutes: [Quickstart: skillctl](../../docs/quickstart-skillctl.md)
- The two-person handover over a real server: [Acceptance and handover](../../docs/acceptance-skillctl-lifecycle.md)
- What this directory is for the maintainer, and the four release gates it asserts:
  [README.md](README.md)
