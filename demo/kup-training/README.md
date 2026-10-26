# KuP Skill-Manager Training: End-to-End Demo

[Deutsch](README.de.md) · [English](README.md)

> **Looking for the tutorial? It is [TUTORIAL.md](TUTORIAL.md).**
> This directory serves two audiences and they want different things.
> **Learner:** you want the 20-minute guided ride that ends with you having broken a
> bundle and watched the tool refuse it. That is `TUTORIAL.md`.
> **Maintainer:** you want the release gate below, which asserts the four contractual
> outputs before a cohort session. That is this file.

Every claim in the Skill-Manager USER-MANUAL (on the private maintenance plane) is proven here by an executable shell script. The orchestrator (`run-all.sh`) is the **release gate**: it asserts the four contractually required outputs.

## Release-gate items

| # | Gate | Proof |
|---|---|---|
| **G1** | Print user guide as PDF | `make-pdf.sh` → `artifacts/{USER-MANUAL,SKILLCTL-MANUAL,KuP-skill-manager-handbook}.pdf` |
| **G2** | Release skillctl via GitHub download + installer | `build-release.sh` → `artifacts/release/{skillctl-*,SHA256SUMS,install.sh,RELEASE_NOTES.md,gh-release-create.sh}` |
| **G3** | Run skill transfer Bob → Alice via aims | `01–05` step scripts; `05` ends with `artifacts/alice-home/output/hello.txt` produced by Alice running a chain-verified skill |
| **G4** | Valid skill works for Alice, invalid skill fails | `05` (valid ✓) + `06`/`07`/`08`/`09` (four distinct invalid scenarios, each asserting the expected non-zero exit) |

## Quick start

```bash
cd demo/kup-training             # from the repository root
./run-all.sh                    # full demo + PDF + release build
./run-all.sh --offline-only     # skip aims-core round-trip (chain proof still runs)
./run-all.sh --no-pdf           # skip PDF render
./run-all.sh --no-release       # skip cross-platform binary build
```

The orchestrator prints a final report mapping every gate item to its proof artifact.

`run-and-prove.sh` is the assertion-level twin: it runs the same chain and checks each step's
load-bearing artifact, not just its exit code.

```bash
./run-and-prove.sh                                  # full chain, fail-fast
./run-and-prove.sh --skip-online --chain-only       # trust chain only: skips G1 (PDF) + G2 (release)
./run-and-prove.sh --keep-going --json out.json     # run everything, emit a summary
```

`--chain-only` exists for the Test Ride: G1 renders a manual from the private maintenance
plane, and without that checkout the whole proof used to abort with rc=1 after every trust
check had passed.

## Steps in order

| File | What it does | Asserts |
|---|---|---|
| `00-preflight.sh` | Builds skillctl from source into `artifacts/bin/`. Probes for online registry. Cleans workspace. | Tools present; binary builds clean |
| `01-bob-author.sh` | Bob: `keygen` → `pack` → `sign` → local `verify-sig`. Confirms determinism (two packs are byte-identical). | Verify-sig exit 0; bundle bytes deterministic |
| `02-bob-publish.sh` | Bob: `skillctl publish --registry self`, the ER1 transport (best-effort online, target `local` by default). | Online: "published to ER1 self"; a failed publish warns and the step still exits 0. Offline: skipped cleanly. |
| `03-reviewer-attest.sh` | Reviewer: `skillctl attest <digest> --level green`. Writes a local `attestation.json` for offline mode. | Online: registry accepts. Offline: attestation.json present, level=green. |
| `04-alice-trust-root.sh` | Alice: `skillctl trust add` to pin Bob's pubkey. | `~/.claude/skill-trust-roots.yaml` contains the pinned key |
| `05-alice-install-and-run.sh` | **Alice: install + verify-sig + extract + run.** Online attempts `skillctl install` first; offline path always runs as the load-bearing chain proof. | `output/hello.txt` produced ✓ |
| `06-invalid-tampered.sh` | Flips one byte in the bundle, keeps the original signature. | `verify-sig` exit **11** (signature invalid) |
| `07-invalid-wrong-key.sh` | Attacker signs a parallel bundle with their own key, claims Bob's identity. | `verify-sig` against Bob's pinned pubkey: exit **11**; control: same bundle exit 0 against attacker's key |
| `08-invalid-no-signature.sh` | Bundle delivered without the matching `<digest>.author.sig`. | `verify-sig` non-zero refusal (no fail-open) |
| `09-invalid-edited-install.sh` | Edits an installed file in place, compares against `CHECKSUMS`. | Mismatch detected; repair restores from signed bundle |

### Steps 10 to 12: the demand side (NOT run by `run-all.sh`)

`run-all.sh` stops after `09`. The three steps below close the supply/demand loop against a
live aims-core and are run by hand; each checks `GET $REGISTRY_URL/api/skills/health` first
and skips itself with a warning when the registry or `ER1_API_KEY` is missing.

| File | What it does | Asserts |
|---|---|---|
| `10-scan-and-sync.sh` | Lifecycle phase SCAN. Projects what is installed on disk into `_user_skill_profiles` via `/api/v2/skills/profile/import`. `--operator` scans the trainer's REAL `~/.claude/skills/` instead of the demo home. | The profile surface reflects installed reality |
| `11-use-skill.sh` | Lifecycle phase USE. Posts five usage events to `/api/v2/skills/usage`. Needs `ER1_CONTEXT_ID` (from `~/.m3c-tools.env`). | `use_count` rises, `last_used` is stamped, mastery moves aware -> practiced |
| `12-decay.sh` | Lifecycle phase DECAY. `POST /api/v2/skills/profile/recalculate-all`. | An unpractised skill decays. Admin route: needs an [admin session](#admin-routes-need-an-admin-session), skips itself without one |

### The workspace is generated, not committed

`artifacts/` is git-ignored and every file under it is produced by a run. It used to be
checked in, including `keys/{bob,reviewer,attacker}.priv`. Git does not preserve mode
`0600`, so every fresh clone landed a world-readable private key, `skillctl sign` fail-closed
on it ("insecure mode 0644"), and step `01` died taking `05`, `06` and `09` with it: the demo
was broken for everyone except the machine that had generated the keys locally. The keys are
regenerated per machine now, `00-preflight.sh` enforces `0600`, and the old committed pair is
retired. If you need a signed demo bundle to look at, run the demo and take it from
`artifacts/bundles/`.

## What gets touched

The demo is **isolated**. It only writes under `artifacts/` (relative to this directory). It uses `artifacts/alice-home/` as a fake `$HOME` for `skillctl trust add` and the install path so your real `~/.claude/` is never modified.

## Online vs offline

| Capability | Offline (always works) | Online (requires `ER1_API_KEY` + reachable aims-core) |
|---|---|---|
| keygen, pack, sign | ✓ | ✓ |
| local verify-sig (chain root) | ✓ | ✓ |
| trust roots (file-based) | ✓ | ✓ |
| Bundle install via registry | _skipped_: replaced with verify-sig + extract | ✓ via `skillctl install` |
| Attestation push | _skipped_: local attestation.json instead | ✓ via `skillctl attest` |
| Identity registration | _skipped_ | ✓ via `POST /api/skills/identities`, in an [admin session](#admin-routes-need-an-admin-session) |

The cryptographic proof is identical in both modes. The registry is the storage substrate, not the trust source. The demo emphasizes this on purpose so the lesson survives a network outage during training.

### Admin routes need an admin session

Two calls in this demo are admin routes on aims-core: registering an identity
(`POST /api/skills/identities`, P0 in `run-and-prove.sh` and `register-identity.sh`) and
`12-decay.sh` (`POST /api/v2/skills/profile/recalculate-all`). They need an authenticated
browser session of a user who is admin by RBAC. The shared `ER1_API_KEY` is never admin,
whatever `X-User-ID` it is sent with, so it cannot register an identity.

Register the two demo identities once, before the online run. Their keys must exist first;
the offline chain generates them, and `00-preflight.sh` keeps them across runs:

```bash
./run-and-prove.sh --skip-online --chain-only           # generates artifacts/keys/{bob,reviewer}.pub
read -rs AIMS_ADMIN_COOKIE && export AIMS_ADMIN_COOKIE  # paste an admin session's Cookie header, then Enter
./register-identity.sh id:bob@m3c      artifacts/keys/bob.pub      "Bob (KuP demo author)"
./register-identity.sh id:reviewer@m3c artifacts/keys/reviewer.pub "Reviewer (KuP demo)"
unset AIMS_ADMIN_COOKIE
./run-and-prove.sh                                      # P0 confirms both with a read: no admin session needed
```

To get the cookie, open `$REGISTRY_URL/v2/skills/admin` in a browser and sign in as an
admin, then copy the value of the `Cookie` request header of any request to the registry
from the developer tools' Network tab. `read -rs` keeps it off the screen and out of shell
history. The scripts hand it to curl on stdin, never as an argument, and send no
`X-API-KEY` and no `Origin` header with it: `skill_registry_bp` is CSRF-exempt behind an
origin check.

An identity stays registered, so later runs need no admin session: `register-identity.sh`
reads `GET /api/skills/identities/<id>` and compares the registered key with the local one.
Exporting `AIMS_ADMIN_COOKIE` before `./run-and-prove.sh` works as well: P0 then registers
whatever is missing as soon as steps 01 and 03 have generated the keys.

| `register-identity.sh` exit | P0 verdict | Meaning |
|---|---|---|
| 0 | green | registered with the local key, just now or earlier |
| 3 | red, sign-in steps printed | not registered (or the read could not confirm it), and no admin session: `AIMS_ADMIN_COOKIE` is unset or not an admin session |
| 4 | red | registered with a different or revoked key. Registering again cannot change that: restore the key pair the registry knows (`00-preflight.sh --reset-all` wipes `artifacts/keys/`) |
| other | yellow | registry unreachable or a server error, see `artifacts/logs/run-and-prove.log` |

`--skip-online` runs no P0 and needs none of this. `12-decay.sh` without `AIMS_ADMIN_COOKIE`
skips itself and prints the same sign-in steps.

## Outputs

After `./run-all.sh`:

```
artifacts/
├── bin/skillctl                              # the binary (matches release/skillctl-*)
├── keys/{bob,reviewer,attacker}.{priv,pub} # ed25519 keypairs
├── bundles/
│   ├── kup-hello-0.1.0.skb                   # the deterministic bundle
│   ├── kup-hello-0.1.0.skb.<digest>.author.sig
│   ├── tampered.skb (+sig)                   # step 06
│   ├── attacker-kup-hello-0.1.0.skb (+sig)   # step 07
│   ├── no-sig/kup-hello-0.1.0.skb            # step 08 (no sig sidecar)
│   └── src/kup-hello/                        # the staged source
├── trust-roots/                              # (handed to Alice in step 04)
├── alice-home/
│   ├── .claude/skill-trust-roots.yaml        # pinned by step 04
│   ├── .claude/skills/kup-hello/             # installed by step 05
│   └── output/hello.txt                      # produced by step 05 ✓
├── attestation.json                          # offline reviewer verdict
├── digest.txt                                # the bundle's sha256:...
├── logs/full.log                             # every captured stderr
├── USER-MANUAL.pdf
├── SKILLCTL-MANUAL.pdf
├── KuP-skill-manager-handbook.pdf
└── release/
    ├── skillctl-darwin-arm64
    ├── skillctl-darwin-amd64
    ├── skillctl-linux-amd64
    ├── skillctl-linux-arm64
    ├── skillctl-windows-amd64.exe
    ├── SHA256SUMS
    ├── install.sh
    ├── RELEASE_NOTES.md
    ├── release-tag.txt
    └── gh-release-create.sh                  # run manually to publish (DRAFT)
```

## Cleaning up

```bash
rm -rf artifacts/
```

That's it: the demo never touches anything outside this directory.

## Where to extend next

- Once SPEC-0194 `propose` lands in the dispatcher, replace step 02's manual multipart POST with `skillctl propose`.
- Once SPEC-0201 `import-public` lands, add `11-airlock-import.sh` to demo upstream-bundle ingestion.
- Once SPEC-0202 `run` lands, replace step 05b's bare bash invocation with `skillctl run` and add a `12-envelope-violation.sh` that triggers exit 32 (egress blocked) deliberately.
