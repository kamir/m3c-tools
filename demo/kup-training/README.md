# KuP Skill-Manager Training — End-to-End Demo

Every claim in [PROJECTS/Skill-Manager/USER-MANUAL.md](../../../m3c-tools-maintenance/PROJECTS/Skill-Manager/USER-MANUAL.md) is proven here by an executable shell script. The orchestrator (`run-all.sh`) is the **release gate**: it asserts the four contractually required outputs.

## Release-gate items

| # | Gate | Proof |
|---|---|---|
| **G1** | Print user guide as PDF | `make-pdf.sh` → `artifacts/{USER-MANUAL,SKILLCTL-MANUAL,KuP-skill-manager-handbook}.pdf` |
| **G2** | Release skillctl via GitHub download + installer | `build-release.sh` → `artifacts/release/{skillctl-*,SHA256SUMS,install.sh,RELEASE_NOTES.md,gh-release-create.sh}` |
| **G3** | Run skill transfer Mirko → Eric via aims | `01–05` step scripts; `05` ends with `artifacts/eric-home/output/hello.txt` produced by Eric running a chain-verified skill |
| **G4** | Valid skill works for Eric, invalid skill fails | `05` (valid ✓) + `06`/`07`/`08`/`09` (four distinct invalid scenarios, each asserting the expected non-zero exit) |

## Quick start

```bash
cd /Users/kamir/GITHUB.kamir/m3c-tools/demo/kup-training
./run-all.sh                    # full demo + PDF + release build
./run-all.sh --offline-only     # skip aims-core round-trip (chain proof still runs)
./run-all.sh --no-pdf           # skip PDF render
./run-all.sh --no-release       # skip cross-platform binary build
```

The orchestrator prints a final report mapping every gate item to its proof artifact.

## Steps in order

| File | What it does | Asserts |
|---|---|---|
| `00-preflight.sh` | Builds skillctl from source into `artifacts/bin/`. Probes for online registry. Cleans workspace. | Tools present; binary builds clean |
| `01-mirko-author.sh` | Mirko: `keygen` → `pack` → `sign` → local `verify-sig`. Confirms determinism (two packs are byte-identical). | Verify-sig exit 0; bundle bytes deterministic |
| `02-mirko-publish.sh` | Mirko: `POST /api/skills/identities` + `POST /api/skills/bundles` (best-effort online). | Online: HTTP 200/201 or 409. Offline: skipped cleanly. |
| `03-reviewer-attest.sh` | Reviewer: `skillctl attest <digest> --level green`. Writes a local `attestation.json` for offline mode. | Online: registry accepts. Offline: attestation.json present, level=green. |
| `04-eric-trust-root.sh` | Eric: `skillctl trust add` to pin Mirko's pubkey. | `~/.claude/skill-trust-roots.yaml` contains the pinned key |
| `05-eric-install-and-run.sh` | **Eric: install + verify-sig + extract + run.** Online attempts `skillctl install` first; offline path always runs as the load-bearing chain proof. | `output/hello.txt` produced ✓ |
| `06-invalid-tampered.sh` | Flips one byte in the bundle, keeps the original signature. | `verify-sig` exit **11** (signature invalid) |
| `07-invalid-wrong-key.sh` | Attacker signs a parallel bundle with their own key, claims Mirko's identity. | `verify-sig` against Mirko's pinned pubkey: exit **11**; control: same bundle exit 0 against attacker's key |
| `08-invalid-no-signature.sh` | Bundle delivered without the matching `<digest>.author.sig`. | `verify-sig` non-zero refusal (no fail-open) |
| `09-invalid-edited-install.sh` | Edits an installed file in place, compares against `CHECKSUMS`. | Mismatch detected; repair restores from signed bundle |

## What gets touched

The demo is **isolated**. It only writes under `artifacts/` (relative to this directory). It uses `artifacts/eric-home/` as a fake `$HOME` for `skillctl trust add` and the install path so your real `~/.claude/` is never modified.

## Online vs offline

| Capability | Offline (always works) | Online (requires `ER1_API_KEY` + reachable aims-core) |
|---|---|---|
| keygen, pack, sign | ✓ | ✓ |
| local verify-sig (chain root) | ✓ | ✓ |
| trust roots (file-based) | ✓ | ✓ |
| Bundle install via registry | _skipped_ — replaced with verify-sig + extract | ✓ via `skillctl install` |
| Attestation push | _skipped_ — local attestation.json instead | ✓ via `skillctl attest` |
| Identity registration | _skipped_ | ✓ via `POST /api/skills/identities` |

The cryptographic proof is identical in both modes — the registry is the storage substrate, not the trust source. The demo emphasizes this on purpose so the lesson survives a network outage during training.

## Outputs

After `./run-all.sh`:

```
artifacts/
├── bin/skillctl                              # the binary (matches release/skillctl-*)
├── keys/{mirko,reviewer,attacker}.{priv,pub} # ed25519 keypairs
├── bundles/
│   ├── kup-hello-0.1.0.skb                   # the deterministic bundle
│   ├── kup-hello-0.1.0.skb.<digest>.author.sig
│   ├── tampered.skb (+sig)                   # step 06
│   ├── attacker-kup-hello-0.1.0.skb (+sig)   # step 07
│   ├── no-sig/kup-hello-0.1.0.skb            # step 08 (no sig sidecar)
│   └── src/kup-hello/                        # the staged source
├── trust-roots/                              # (handed to Eric in step 04)
├── eric-home/
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

That's it — the demo never touches anything outside this directory.

## Where to extend next

- Once SPEC-0194 `propose` lands in the dispatcher, replace step 02's manual multipart POST with `skillctl propose`.
- Once SPEC-0201 `import-public` lands, add `11-airlock-import.sh` to demo upstream-bundle ingestion.
- Once SPEC-0202 `run` lands, replace step 05b's bare bash invocation with `skillctl run` and add a `12-envelope-violation.sh` that triggers exit 32 (egress blocked) deliberately.
