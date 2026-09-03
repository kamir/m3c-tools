---
layout: default
title: Bug & feature tracking
---

# Bug & feature tracking — the two planes

A bug or a feature request lives in **two places**, and `scripts/bugtracker.sh` keeps them
in step.

| Plane | Where | Holds |
|-------|-------|-------|
| **Analysis** (private) | `$M3C_MAINTENANCE_DIR/bug-reports/<KIND>-NNNN-<slug>.md` | Everything: root cause or rationale, `file:line`, customer context, SPEC references. The source of truth. |
| **Issue** (public) | a GitHub issue in the repository the item names | A **redacted restatement**: observed, expected, reproduction, version. Refers to the analysis **ID-only** (`BUG-0213`). |

The issue is **never a copy** of the analysis. `bug-reports/` also holds items for systems
this repository does not ship; those never leave the private plane.

Two kinds of item, differing on exactly one word:

| Kind | Closes as | Issue label |
|------|-----------|-------------|
| `BUG-NNNN` | `fixed` | `bug` |
| `FR-NNNN` | `implemented` | `enhancement` |

Ids resolve by kind — `BUG-0213`, `FR-0096`, `fr-96`, or a filename. A **bare number means
a BUG**, so `96` can never silently resolve to the wrong item.

---

## Setup

```bash
export M3C_MAINTENANCE_DIR="$HOME/path/to/your-maintenance-repo"
```

That is the only variable you need. The target repository for an issue is **not** taken
from the environment or from your working directory — see
[Which repository an issue goes to](#which-repository-an-issue-goes-to).

---

## The item file

Five lines are machine-read. Keep their exact spelling; the rest of the file is prose for
humans.

| Field | Meaning |
|-------|---------|
| `- **Status:**` | `open` · `in-progress` · `fixed` (BUG) / `implemented` (FR) · `wontfix` · `duplicate` |
| `- **Public:**` | `yes` opts this item into a public issue. Anything else keeps it private. |
| `- **Repo:**` | `owner/repo` the issue belongs in. Declared here because it is reviewed here. |
| `- **Spec:**` | Which SPEC this serves. `none — <reason>` is a valid answer; a missing line is not. |
| `- **Issue:**` | Written back by `open`: `owner/repo#42`. After that it is the authoritative target. |

Reading tolerates the corpus as it stands — `**Status:** Fixed (2026-03-21)` reads as
`fixed` — while writing is always canonical, so `sync` has something to parse.

---

## Commands

```bash
scripts/bugtracker.sh <command> [args]
```

| Command | Purpose |
|---------|---------|
| `next-id [BUG\|FR] [--no-fetch]` | Next free id of that kind (default `BUG`). Use it instead of counting files — see [Allocating an id](#allocating-an-id). |
| `path <ID>` | Resolve the analysis file. |
| `status <ID> [STATUS]` | Read, or set, the canonical status. |
| `issue <ID>` | The linked issue reference, or empty for a private-only item. |
| `spec <ID>` | The SPEC this item answers to. |
| `redact-check [FILE\|-]` | Run the leak patterns over text. Exit `1` on a hit. |
| `open <ID>` | Create the public issue and link it back. |
| `close <ID> [--status S] [--comment TEXT]` | Set the status and close the issue. |
| `sync [<ID>]` | Read-only: report the drift between file and issue. |

Exit codes: `0` ok · `1` a check failed (drift, leak, refusal) · `2` usage or configuration
error.

---

## Allocating an id

`next-id` fetches first, then takes the ceiling from **every** place a number can
already be claimed:

1. a file in the local `bug-reports/`
2. a file on **any** local or remote branch — someone else's unmerged work
3. a **branch name** like `docs/fr-0096-…`

The third matters more than it looks: a branch is usually named before its file
is written, so it is the earliest visible claim there is. When the ceiling comes
from outside your working tree, `next-id` says so on stderr rather than silently
handing you a number someone else is already using.

```
next-id: highest FR claim is FR-0005 in branch docs/fr-0005-… — not in your working tree
FR-0006
```

`--no-fetch` skips the network; the answer is then only as fresh as your last
pull.

> **This is mitigation, not a fix.** Allocation is still a *read*: two sessions
> asking in the same moment still get the same number, because nothing records
> that the first one took it. The durable answer is to make allocation a write —
> the slot table that already governs SPEC ids does exactly that, and extending
> it to FR and BUG is tracked separately.

---

## Filing a bug

```bash
scripts/bugtracker.sh next-id                    # -> BUG-0213
```

Write `$M3C_MAINTENANCE_DIR/bug-reports/BUG-0213-<slug>.md` with the five fields above and
the analysis. If it stays private, you are done.

For a public bug, write the redacted body next to it as
`BUG-0213-<slug>.public.md` — **line 1 is the issue title**, the rest is the body — then:

```bash
scripts/bugtracker.sh open BUG-0213
```

The `/bug-report` skill does all of this from a field observation.

## Raising a feature request

```bash
scripts/bugtracker.sh next-id FR                 # -> FR-0096
```

Same shape, with two differences worth knowing:

- A proposal is rarely **one** request. Split it where the asks could be accepted,
  rejected, scheduled or built independently — and keep the author's own numbering out of
  this repository's id space; record it in the body instead.
- Several FRs from one proposal usually share **one** contract. Prefer a single SPEC with a
  section per area over one SPEC per FR: a contract scattered across seven documents has
  stopped being a contract.

The `/feature-request` skill runs that flow.

## Closing

```bash
scripts/bugtracker.sh close BUG-0213 --comment "Fixed in v2.11.1 — see BUG-0213."
scripts/bugtracker.sh sync  BUG-0213
```

`close` sets the status and, if an issue is linked, comments and closes it. Use
`--status wontfix` or `--status duplicate` when that is the honest outcome; those close the
issue as *not planned*. `sync` exits `0` when the file and the issue tell the same story.

---

## The refusals, and why they exist

A public issue is indexed the moment it is created and cannot be un-published. Every guard
below therefore fails **closed** — it stops rather than guesses.

| `open` refuses when | Fix it by |
|---------------------|-----------|
| the item does not declare `- **Public:** yes` | deciding the plane deliberately, per item |
| there is no `.public.md` body | writing the redacted restatement |
| the body carries private-plane content | rewriting the body — **never** by working around the refusal |
| no repository is named | adding the `- **Repo:**` line |

| `close` refuses when | Fix it by |
|----------------------|-----------|
| the item has no `- **Spec:**` line and is being closed as done | answering the question — including `none — <reason>` |
| a `--comment` carries private-plane content | rewriting the comment |

The Spec rule is the mechanical form of a working rule: **solving an issue means serving
the contract it belongs to.** It deliberately does not demand a *particular* answer; it
only prevents the question from being skipped instead of decided, which is how "update the
SPEC" quietly stops happening.

---

## Redaction

The issue is written for someone who cannot read the private plane. If the body only makes
sense with the internal document open, it is not finished.

| Keep | Drop |
|------|------|
| observed behaviour, expected behaviour | a path into the private repo |
| reproduction, affected version | internal endpoints and API paths |
| the user-visible command and its output | ER1 context-ids, secret header names |
| acceptance criteria | customer or tenant names |
| ID-only references (`BUG-0213`, `SPEC-0401`) | SPEC *paths* — the id alone is fine |

The patterns are not a second opinion: they live in `tools/leak-patterns.txt` and are read
by **both** gates —

- `tools/boundary-gate.sh`, the **commit** gate that runs in CI over tracked files, and
- `scripts/bugtracker.sh`, the **post** gate over issue bodies and comments.

An issue body reaches GitHub through the API, so no CI job ever sees it. That is why the
second consumer exists, and why the patterns are defined once: a sixth pattern added to
the commit gate alone would leave the publishing path unchanged, silently.

Check any text yourself:

```bash
printf 'Observed: the last frame is dropped. See BUG-0213.\n' \
  | scripts/bugtracker.sh redact-check -
```

---

## Which repository an issue goes to

The target is a property of the **item**, never of your working directory. Resolution runs
most-authoritative-first:

1. the recorded `- **Issue:** owner/repo#N` — after creation, this *is* the fact
2. the declared `- **Repo:** owner/repo` — before creation, reviewed in the file
3. `$M3C_BUG_REPO` — a stated override for a one-off
4. otherwise it **refuses**, naming the line to add

The file outranks the environment on purpose: an item that has declared its target must
not be redirected elsewhere by a stray variable.

> **Why there is no fallback to `git remote origin`.** `bug-reports/` holds items for
> several systems, so there is no single correct default to infer — and a default that
> varies with where you happen to stand is exactly how an issue lands in the wrong
> repository, including someone else's public one.

---

## Testing

Both fixture suites are pure bash, touch no network, and run in the `boundary-gate`
workflow on every push:

```bash
tools/boundary-gate.test.sh     # every leak pattern still blocks
scripts/bugtracker.test.sh      # the tracker, with a stubbed gh
```

The first exists because a leak gate that stops flagging still reads green, so it is
asserted from the failing side. The second is mostly refusals, for the same reason the
guards above are: publishing cannot be undone.

---

## See also

- [Manual: m3c-tools](manual-m3c-tools.md) — the capture toolkit, command by command
- [Manual: skillctl](manual-skillctl.md) — the agent-skill trust lifecycle
