# CodeQL alert backlog and repository security posture

Status: 2026-09-04. Owner: whoever merges next.

This file exists because the `Code scanning results / CodeQL` check goes red on
pull requests that changed nothing dangerous, and "the check is always red" is
how a real finding gets missed. It records what each open alert is, what was
done about it, and what is deliberately left open.

---

## Why the check goes red on an unrelated PR

GitHub attributes a code-scanning alert to a pull request when the PR **touches
the file the alert is in**, not only when the PR introduces it. A comment-only
change to a file that already carries an alert therefore surfaces that alert as
"new" on the PR.

That is exactly what happened on PR #176 (the em dash sweep): it edited comments
and message strings in six files, and CodeQL reported "8 new alerts including 1
critical" although every one of them was already open on `master` at the same
rule, path and line.

**How to tell the two apart**, in two commands:

```bash
# 1. the alerts as they stand on the default branch
gh api "repos/<owner>/<repo>/code-scanning/alerts?ref=refs/heads/master&state=open" \
  --jq '.[] | "\(.rule.id)\t\(.most_recent_instance.location.path):\(.most_recent_instance.location.start_line)"'

# 2. the same query with ref=refs/pull/<N>/head, then diff the two lists
```

If a PR's list is a subset of master's list, the PR introduced nothing. Then
check whether any line the PR actually changed coincides with an alert line; if
none do, the attribution is positional only.

---

## The alerts, one by one

Nine alerts were open on `master` when this file was written: one critical and
eight high.

### Fixed in code

| Rule | Location | What was actually wrong |
|---|---|---|
| `go/request-forgery` (critical) | `pkg/setup/pocket_validate.go` | Real SSRF primitive. `baseURL` arrives from a JSON body on the loopback config-editor API (`handleValidatePocketKey`), and the request built from it carries the user's Pocket API key in an `Authorization: Bearer` header. Nothing constrained the destination, so a caller chose where the credential was sent. |
| `go/path-injection` (4 alerts) | `pkg/config/profile.go` | Real path traversal. **There was no profile-name validator at all.** A profile name becomes `profilesDir()/<name>.env`, so `../../tmp/x` escaped the profiles directory on read, write and delete. Reachable from the CLI and from the config-editor API. |
| `go/clear-text-logging` | `pkg/er1/config.go` | The FATAL placeholder line logged `cfg.APIKey` verbatim. The value is a known placeholder at that point, so no live secret was written, but the redaction depended on `IsBlockingPlaceholder` staying correct forever. |

**What changed.**

- `pkg/config/profile.go` gained `ValidateProfileName` (an allow-list: letters,
  digits, `.`, `_`, `-`; no leading dot; 64 characters) and `profilePath`, the
  single place a name becomes a path. `GetProfile`, `CreateProfile`,
  `DeleteProfile` and `ImportProfile` all go through it, so a new call site
  cannot forget the check. `ActiveProfileName` validates on **read-back** too:
  the active-profile file is plain text on disk, and a traversal name written
  into it must not come back as a trusted name. It reports "no active profile"
  instead.
- `pkg/setup/pocket_validate.go` gained `checkPocketBaseURL`, which parses the
  URL and refuses any host outside the Pocket allow-list, any non-http(s)
  scheme, and plain `http` to anything but loopback. Loopback stays allowed on
  purpose: the tests and the local mock point at `127.0.0.1`, and a request to
  your own machine cannot exfiltrate anything.
- `pkg/er1/config.go` now logs `config.MaskAPIKey(cfg.APIKey)`. The placeholder
  is still recognisable from its first and last four characters, and no future
  change to the predicate can put a real key into a log file.

Each fix has a **negative control**: with the guard removed, the new test fails.
For the SSRF test the negative control is visible in the clock, the suite goes
from under a second to 75 seconds, because without the allow-list the process
really does dial the foreign host with the credential attached.

### Restructured so the guard is enforced rather than argued

| Rule | Location | Assessment |
|---|---|---|
| `go/disabled-certificate-check` | `cmd/skillctl/replay_cmds.go` | Not a defect, but the safety argument lived in a comment. `InsecureSkipVerify` was selected by the `--target` string, on the reasoning that `target=="local"` always resolves to `https://127.0.0.1:8081`. True, and unenforced: an edit to `defaultReplayBaseURL` could have falsified it silently. |

`newReplayHTTPClient` now takes the **URL actually being requested** and checks
that its host is loopback (`net.IP.IsLoopback`, plus `localhost`). Anything else,
including a parse failure and a loopback-looking name such as
`127.0.0.1.evil.example.com`, falls through to the verifying client. Fail closed
rather than fail argued.

The alert stays open: CodeQL flags the `InsecureSkipVerify` literal without
modelling the guard above it.

### Open by decision, with the reason

| Rule | Location | Why it stays |
|---|---|---|
| `go/zipslip` | `pkg/skillbundle/unpack.go` | **False positive.** `sanitizeArchivePath` rejects NUL bytes, backslashes, colons (the NTFS ADS and drive separator), absolute paths, `..` traversal and Windows volume prefixes, and the extraction joins under a resolved destination root. CodeQL does not model the custom sanitizer, so it sees an unsanitized `tar.Header.Name` reaching a file operation. Rewriting working, well-reasoned traversal defence to satisfy a query that cannot see it would trade real safety for a green tick. |
| `go/weak-sensitive-data-hashing` | `pkg/pocket/syncapi.go` | **Misclassification, and changing it would cost data.** `DeriveAccountID` derives a stable identifier from a high-entropy `pk_` API key with SHA-256. It is not password storage, so "not computationally expensive" does not apply; brute-forcing a `pk_` key through the hash is not a practical attack. More importantly the derived id is **persisted in existing sync ledgers**, so switching to HMAC or a slow KDF would orphan every already-synced account. The alert is accepted, not fixed. |

Both are now **dismissed** in Code Scanning with those reasons recorded on the
alert (`go/zipslip` as "false positive", `go/weak-sensitive-data-hashing` as
"won't fix"). Dismissal is an account action, not a code change: no commit
removes an alert that CodeQL believes in. If either is ever reopened, this
section is the reason it was closed.

A third alert, `go/disabled-certificate-check` on `cmd/skillctl/replay_cmds.go`,
is dismissed once the restructure above is on the default branch: the loopback
property is checked at runtime on the URL being requested, and CodeQL flags the
`InsecureSkipVerify` literal without seeing the guard.

---

## The gosec baseline moved, and why

`scripts/gosec-diff-gate.sh` compares against a committed signature baseline
(`docs/security/gosec-inci-baseline.txt`), where a signature is
`rule_id + file + normalized snippet`. The fixes above moved it by 7 lines. All
7 are accounted for, and none is a new risk introduced by this change:

- **1 changed.** `G703 pkg/config/profile.go`: `DeleteProfile` no longer builds
  its path with an inline `filepath.Join`, it calls `profilePath`. Same finding,
  new snippet text.
- **5 added, all in code this change did not touch.** Two `G704` and two `G706`
  in `pkg/config/healthcheck.go`, one `G706` in `ApplyProfile`. The `G70x`
  family is gosec's taint analysis, which follows flows across functions inside
  a package. Introducing `ValidateProfileName` and `profilePath` changed the
  call graph of `pkg/config`, and the engine now reaches sources it did not
  reach before. The flagged lines themselves are unchanged and pre-existing.

Assessed rather than waved through:

- `G706` on `ApplyProfile` is log injection through a profile name. That one had
  a real edge: `ParseEnvFile` overrides the name from the file's own
  `# M3C Profile:` header, an imported `.env` is foreign content, and a carriage
  return survives both the line split and the trim. It is closed here by
  `stripControl` on the header name and description, with a test. The alert
  still fires because gosec does not model the sanitizer.
- `G706` and `G704` in `healthcheck.go` are the ER1 base URL flowing into a
  request and into a warning line. Same class as the `go/request-forgery` alert
  fixed above but on the operator's own configured endpoint rather than on a
  value from an HTTP body, so there is no third party to redirect it. Accepted.

The baseline was regenerated with the pinned `gosec@v2.29.0`, not hand-edited.

---

## Repository posture, as measured

Two facts worth stating plainly, because they change what "the gate is green"
is worth:

**`master` has no branch protection and no rulesets.** Verified with:

```bash
gh api repos/<owner>/<repo>/branches/master/protection   # 404 Branch not protected
gh api repos/<owner>/<repo>/rulesets                     # empty
```

So there are **zero required status checks**. Every gate this repository builds,
`prose-gate`, the docaudit CLI/manual gate, the gosec no-new-findings diff gate,
`boundary-gate`, the race suites, is advisory in the only sense that matters:
nothing prevents a merge while one of them is red. The gates still do their job
for anyone who reads them; they simply do not block.

**Secret-scanning push protection is off** (secret scanning itself and
Dependabot security updates are on).

### The user-only actions

These need repository-admin rights and cannot be done from a pull request.

1. **Protect `master`** (Settings, Branches, or a ruleset) and require these
   checks, which are the names CI reports today:

   ```
   Lint & Vet
   Unit Tests
   skillctl Security Tests (-race)
   CLI/manual consistency (docaudit)
   Prose (no em dash)
   gitleaks (secret scan)
   govulncheck (reachable CVEs)
   go mod tidy is a no-op
   boundary-gate
   gosec no-new-findings (in-CI diff gate)
   Ratchet coverage (skillctl trust surface)
   Validate branch name
   CodeQL
   ```

   These are the check-run names exactly as reported. Two traps: the code
   scanning check is called plain **`CodeQL`**, not "Code scanning results /
   CodeQL"; and the `gosec` check run reports **skipped** on most runs, so it is
   deliberately not in the list.

   `CodeQL` only belongs in that list **after** the accepted alerts are
   dismissed, otherwise it blocks every pull request on findings this file
   documents as accepted.

   Verify with:

   ```bash
   gh api repos/<owner>/<repo>/branches/master/protection \
     --jq '{required: .required_status_checks.contexts, strict: .required_status_checks.strict, admins: .enforce_admins.enabled}'
   ```

2. **Turn on secret-scanning push protection** (Settings, Code security). It
   refuses a push that contains a recognised credential, which is strictly
   earlier than the gitleaks job.

---

## Re-checking this file

```bash
# what is open right now on the default branch
gh api "repos/<owner>/<repo>/code-scanning/alerts?ref=refs/heads/master&state=open" \
  --jq '.[] | "\(.rule.security_severity_level)\t\(.rule.id)\t\(.most_recent_instance.location.path):\(.most_recent_instance.location.start_line)"' | sort

# the local gates
make check-emdash
./scripts/gosec-diff-gate.sh
go run ./cmd/docaudit -cli all
./tools/boundary-gate.sh
```

If the alert list stops matching the table above, this file is stale. Update it
in the same PR that changed the code, not later.
