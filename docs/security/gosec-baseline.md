# gosec baseline

`gosec-baseline.sarif` is a point-in-time snapshot of the static-analysis
findings from [gosec](https://github.com/securego/gosec) over the whole module.
It exists so a **future** CI gate can start green (fail only on *new* findings)
rather than drowning in the pre-existing backlog. **No CI job is wired yet** —
that decision is pending; this is only the artifact + triage note.

## How it was generated

```bash
gosec -track-suppressions -fmt sarif -out docs/security/gosec-baseline.sarif ./...
```

- `gosec dev` (installed via `go install github.com/securego/gosec/v2/cmd/gosec@latest`)
- Go 1.26.x, generated 2026-09-03, against branch `fix/skillctl-gosec-real-findings`.
- `-track-suppressions` keeps `#nosec`-annotated sites **in** the SARIF as
  `suppressions` entries (rather than dropping them), so the gate can tell an
  intentional, justified suppression apart from an un-triaged finding.

Regenerate the same way after intentional changes; gosec exits non-zero whenever
it reports any finding, so a non-zero exit here is expected.

## What's in it

**505 findings total: 501 active + 4 tracked-suppressed.**

Active findings by rule (highest first):

| Rule  | Count | What it flags | Triage |
|-------|------:|---------------|--------|
| G304  | 148 | File path from a variable (potential path traversal) | Bulk-defer. Mostly CLI/config reading operator-supplied paths; not attacker-tainted. Review case-by-case; not a blocker. |
| G104  |  73 | Unhandled error | Bulk-defer. Backlog after this PR fixed the security-relevant ones (retry-queue persistence, trust-seal write, config apply). |
| G703  |  52 | Errors unhandled (audit variant) | Bulk-defer with G104. |
| G115  |  45 | Integer overflow on conversion | Bulk-defer. Concentrated in WAV/audio byte packing (`byte(v>>8)` — intended truncation). |
| G204  |  42 | Subprocess launched with variable | Bulk-defer. whisper / ffmpeg / tool wrappers; args are program-controlled, review for injection. |
| G301/G302/G306 | 79 | Poor file/dir permissions | Bulk-defer; BOTH trust-seal write paths (review-server `handleSeal` + scanner `delta.SealStore.Seal`) were tightened 0644→0600 (dir 0755→0700) in this PR. Re-audit any 0644/0777 on secret-bearing paths. |
| G706  |  22 | (audit) | Bulk-defer. |
| **G402** | **14** | **TLS InsecureSkipVerify** | **Partly triaged (see below).** The 4 named trust-path sites are annotated + suppressed. The remaining 14 are other clients (er1/upload, plaud, pocket, health-check) that share the same loopback-gated `VerifySSL`/`ER1_VERIFY_SSL` pattern — should be verified + annotated in a follow-up. |
| G704  |   6 | Variable used as HTTP request URL (SSRF surface) | Partly triaged. The revoke path is validated (`validateRegistryURL`) + cross-host-redirect-locked in this PR; the rest are operator-configured registry/ER1 URLs — review each for origin constraints. |
| others |  ~15 | G112/G705/G202/G404/G101/G122/G702/G124/G203/G117 | Bulk-defer; low volume, review individually. |

## Suppressed (intentional, justified) — `#nosec G402`

These four TLS-skip sites are gated dev/self-signed support, **secure by
default** (verification on unless an explicit opt-out AND a loopback target).
Each carries a `#nosec G402 -- <reason>` directive; the reasoning and the
default-verifies regression tests landed alongside this note.

| File | Line | Gate |
|------|-----:|------|
| `pkg/skillctl/registry/er1_room.go`    | ~192 | `er1TLSGuard` fails closed for non-loopback; `applyTLSVerificationPolicy` forces verify on at load |
| `pkg/skillctl/registry/er1_publish.go` | ~552 | same as above |
| `cmd/skillctl/sync_cmds.go`            | ~178 | `--insecure` + `isLoopbackHost` only; endpoint must be https |
| `cmd/skillctl/replay_cmds.go`          | ~412 | `target==local` only → hardcoded loopback base URL |

## Not done here (deliberately)

- No CI wiring. When a gate is added, run gosec against this baseline
  (`gosec -baseline docs/security/gosec-baseline.sarif ...` once regenerated
  under the same gosec version) so only regressions fail the build.
- The G402/G704/G304/G104 backlog above is triaged-for-severity, not fixed. The
  trust-path items in each category were fixed in this PR; the rest are the
  next security-hygiene sweep.
