# gosec alert backlog and what each class still needs

Status: 2026-09-15. Owner: whoever merges next.

This is the gosec counterpart to [codeql-backlog.md](codeql-backlog.md), and it
exists for a sharper reason than its sibling. CodeQL's backlog documents alerts
everyone could see. gosec's alerts **could not be seen at all** until today.

## Why this file did not exist until now

Code Scanning recorded 344 gosec analyses between 2026-09-03 and 2026-09-15.
**343 of them carry `results_count: 0`.** The runs arrived, every finding in
them was discarded over a malformed location, and the Actions job reported
success every single time. The full derivation is BUG-0440 in the maintenance
canon; the fix is PR #298.

A tool missing from the dashboard is visibly missing. A tool present with zero
findings reads as a clean bill of health. That is the whole reason this file
opens with a number instead of a list.

### The query that lies

```bash
gh api 'repos/kamir/m3c-tools/code-scanning/analyses?tool_name=gosec'   # -> []
```

That empty list means **no tool by that name**, not **no analyses**. The SARIF
calls the tool `Golang security checks by gosec`, and the filter compares the
string exactly. Use:

```bash
gh api 'repos/kamir/m3c-tools/code-scanning/analyses\
        ?tool_name=Golang%20security%20checks%20by%20gosec'
```

## Two flags, and why the run looks the way it does

### `-track-suppressions` is deliberately absent

The flag kept excluded and `#nosec`-justified findings in the document with a
`suppressions` block attached, so that a justified suppression stayed
distinguishable from an untriaged finding. On this surface it achieves the
opposite. **Measured 2026-09-15: Code Scanning ignores the block and lists such
findings as OPEN.** Three samples, all carrying `#nosec` in code, all open:
`pkg/skillctl/registry/er1_room.go:193` (alert #35),
`cmd/skillctl/sync_cmds.go:178` (#46),
`pkg/skillctl/install/install_bundle.go:219` (#63).

```
with -track-suppressions                  502 uploaded -> 502 open
-exclude=G104 with -track-suppressions    502 uploaded -> 502 open   (no effect)
-exclude=G104 without -track-suppressions 401 uploaded -> 401 open
```

The distinction is not lost, it moves to where it is read: the `#nosec` comment
in the source, and the diff-gate baseline. The dashboard was never its home.

### `-exclude=G104` applies to THIS surface only

G104 "Errors unhandled" produced 72 of the original 502 alerts. **71 of them sit
on lines that already carry `//nolint:errcheck` with a written reason.**
errcheck owns that question, `.golangci.yml` carries a carefully derived policy
for it, including the rule "exception at the call site, not by operation class".
Maintaining the same exceptions twice does not produce security, it produces two
places where one decision can rot.

This opens no hole. `scripts/gosec-diff-gate.sh` calls gosec independently in
`run_gosec()` **without** this flag, and the baseline keeps its 70 G104
signatures. A genuinely new unhandled error still trips that gate. Only the
alert backlog lost the class.

The 72nd had no reason at its call site: `pkg/timetracking/gantt.go:98`,
`h.Write([]byte(projectID))` on an `fnv.New32a()`. `hash.Hash.Write` never
returns an error by documented contract; the return pair exists only because
`hash.Hash` is an `io.Writer`. It now carries a `#nosec G104` naming that
contract, which stays correct if G104 is ever switched back on.

## What is left: 401 findings

| Rule | Findings | Files | Severity | Confidence | What it reports |
|---|---:|---:|---|---|---|
| `G304` | 148 | 85 | MEDIUM | high | Potential file inclusion via variable |
| `G703` | 52 | 23 | **HIGH** | high | Path traversal via taint analysis |
| `G204` | 42 | 19 | MEDIUM | high | Subprocess launched with variable |
| `G301` | 37 | 23 | MEDIUM | high | Directory permissions expected 0750 or less |
| `G306` | 34 | 27 | MEDIUM | high | WriteFile permissions expected 0600 or less |
| `G706` | 25 | 5 | LOW | high | Log injection via taint analysis |
| `G115` | 22 | 8 | **HIGH** | medium | Integer overflow conversion |
| `G402` | 14 | 10 | **HIGH** | high | TLS InsecureSkipVerify set to true |
| `G704` | 8 | 4 | **HIGH** | high | SSRF via taint analysis |
| `G112` | 5 | 5 | MEDIUM | low | ReadHeaderTimeout not configured |
| `G302` | 3 | 3 | MEDIUM | high | File permissions expected 0600 or less |
| `G705` | 2 | 2 | MEDIUM | high | XSS via taint analysis |
| `G202` | 2 | 1 | MEDIUM | high | SQL string concatenation |
| `G404` | 1 | 1 | **HIGH** | medium | Weak random number generator |
| `G101` | 1 | 1 | **HIGH** | low | Potential hardcoded credentials |
| `G122` | 1 | 1 | **HIGH** | medium | Symlink TOCTOU in a Walk callback |
| `G702` | 1 | 1 | **HIGH** | high | Command injection via taint analysis |
| `G124` | 1 | 1 | MEDIUM | high | Cookie missing Secure/HttpOnly/SameSite |
| `G203` | 1 | 1 | MEDIUM | low | Non-auto-escaping HTML method |
| `G117` | 1 | 1 | MEDIUM | medium | Marshaled field `AccessToken` matches a secret pattern |

All 401 are in production code. gosec does not read `_test.go` by default, so
none of this is test scaffolding.

## What this backlog is NOT

It is not a triage. Nobody has read these 401 findings. The diff-gate baseline
has enumerated them since 2026-09-10, which froze the backlog; freezing is not
reading. A signature file can say "add no more". It cannot say "we looked at
this one and it is fine because X". That sentence now has a place, and it is
still empty.

## What actually needs a decision, in the order it is worth doing

The size of a class is a poor guide. Severity times confidence times blast
radius is a better one.

**1. The sharp singletons, 11 findings.** `G702` command injection (1),
`G704` SSRF (8), `G122` symlink TOCTOU (1), `G117` a marshaled `AccessToken`
(1). All HIGH, most high confidence, each small enough to read in one sitting.
This is the cheapest real security work in the list.

**2. `G402` TLS InsecureSkipVerify, 14 in 10 files.** HIGH and high confidence,
and the four that were already `#nosec`ed show the decision has been made
before. Either the remaining 14 have the same justification, in which case they
should carry it at the call site, or they do not, in which case they are a
finding.

**3. `G703` path traversal, 52 in 23 files.** The largest HIGH class. Needs
actual review, not a class verdict, because "is this path attacker-controlled"
is a per-site question. Concentrated in CLI entry points.

**4. The mechanical classes, 261 findings.** `G304` (148), `G204` (42),
`G301` (37), `G306` (34). These want ONE written class decision each, not 261
individual ones. The question per class is the same shape: is the variable
reachable from untrusted input in this program, and if not, what makes that
structurally true rather than currently true.

**5. `G706` log injection (25) and `G115` integer overflow (22).** Low severity
or medium confidence. Worth a class decision, last.

Note on `G115`: 23 further findings exist that can never appear here at all.
They sit in cgo-generated Go, which has no repository file to name, so they
carry an empty `artifactLocation` and are dropped by
`scripts/sarif-for-code-scanning.py`. They are counted in its log, not here.

## Re-checking this file

```bash
# what is open right now on the default branch
gh api --paginate 'repos/kamir/m3c-tools/code-scanning/alerts?state=open&per_page=100' \
  --jq '.[] | "\(.rule.id)\t\(.most_recent_instance.location.path)"' | sort | uniq -c | sort -rn

# the analyses, with the tool name spelled the way the SARIF spells it
gh api 'repos/kamir/m3c-tools/code-scanning/analyses\
        ?tool_name=Golang%20security%20checks%20by%20gosec&per_page=5' \
  --jq '.[] | "\(.created_at) ref=\(.ref) results=\(.results_count)"'

# the local gate that still covers G104
./scripts/gosec-diff-gate.sh
```
