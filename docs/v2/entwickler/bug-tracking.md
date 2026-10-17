---
layout: default
title: Bug & feature tracking
---

# Bug & feature tracking: the two planes

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

Ids resolve by kind: `BUG-0213`, `FR-0096`, `fr-96`, or a filename. A **bare number means
a BUG**, so `96` can never silently resolve to the wrong item.

---

## Setup

```bash
export M3C_MAINTENANCE_DIR="$HOME/path/to/your-maintenance-repo"
```

That is the only variable you need. The target repository for an issue is **not** taken
from the environment or from your working directory. See
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
| `- **Spec:**` | Which SPEC this serves. `none: <reason>` is a valid answer; a missing line is not. |
| `- **Issue:**` | Written back by `open`: `owner/repo#42`. After that it is the authoritative target. |

Reading tolerates the corpus as it stands, `**Status:** Fixed (2026-03-21)` reads as
`fixed`, while writing is always canonical, so `sync` has something to parse.

---

## Commands

```bash
scripts/bugtracker.sh <command> [args]
```

| Command | Purpose |
|---------|---------|
| `next-id [BUG\|FR] [--no-fetch]` | Next free id of that kind (default `BUG`). Use it instead of counting files: see [Allocating an id](#allocating-an-id). |
| `claim <ID>` | Record the id in the shared slot table. **This** is what allocates it. |
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
2. a file on **any** local or remote branch: someone else's unmerged work
3. a **branch name** like `docs/fr-0096-…`

The third matters more than it looks: a branch is usually named before its file
is written, so it is the earliest visible claim there is. When the ceiling comes
from outside your working tree, `next-id` says so on stderr rather than silently
handing you a number someone else is already using.

```
next-id: highest FR claim is FR-0005 in branch docs/fr-0005-…, not in your working tree
FR-0006
```

`--no-fetch` skips the network; the answer is then only as fresh as your last
pull.

### Claiming it

`next-id` only **reads**. Two sessions asking in the same moment still get the
same number, because reading a ceiling records nothing; that is exactly how one
id was handed out twice. The write is a separate step:

```bash
scripts/bugtracker.sh next-id FR          # FR-0105  (a ceiling, not a claim)
# … write the report file …
scripts/bugtracker.sh claim FR-0105       # exit 0: now it is allocated
```

`claim` establishes the pair of id and **filename** on the branch that holds the
shared slot table: it reads that branch from the remote, adds one row in a commit
of its own, and pushes it. **Exit 0 means the push was accepted**, or the branch
already carried the same number for the same file.

`claim` refuses before it commits or pushes anything, and so writes nothing,
when:

- the number already belongs to a different file on the remote: it names who
  holds it and that the later one yields, also when your own clone has not
  heard of it yet;
- the table has no `ANKER` row, more than one, or does not end with a newline.
  New rows go directly under the `ANKER` row, and `claim` does not repair a
  table, not even a missing final newline;
- the report's filename is not a plain identifier. After `BUG-<number>-` or
  `FR-<number>-` it may hold letters, digits, dot, underscore and dash, and it
  ends in `.md`. Backtick, pipe, backslash, spaces and line breaks would end
  the table cell early, and the row `claim` writes must read back as exactly
  one entry for that number and that file;
- git configuration is set in the environment (`GIT_CONFIG_PARAMETERS`,
  `GIT_CONFIG_COUNT`, `GIT_CONFIG`), for instance by `git -c ...` around the
  call. `claim` cannot check it and does not run with it;
- it is not plain which repository the remote names: the remote has more than
  one `url`, or any `pushurl`; a `url.*.insteadOf` or `url.*.pushInsteadOf`
  rule from git's config files rewrites where it fetches from or pushes to;
  the url has no `/` and no `:`, so git could take it for a remote's name
  (write `./name` instead); there is an old-style remote file for it under
  `.git/remotes` or `.git/branches`; or it is the name of a configured remote.
  These are the cases `claim` knows. It does not model git's URL handling,
  and within these cases it refuses also where the configuration would have
  been harmless;
- a hook of the table's repository refuses the commit, or the commit that comes
  out is not the authorised change. Before pushing, `claim` reads the commit
  back from git: its only parent is the commit that was read, and it changes
  one path, the table, to the table as read plus the one row, with the file
  mode unchanged. A hook that stages another file, reformats the table, drops
  a row or commits again therefore stops the claim. This is a check against
  accidents, not a defence: a hook written to work against `claim` runs with
  your rights in your repository and is outside what `claim` can guard;

Once it pushes, the end can be different. A push that is not confirmed starts
a new round: `claim` reads the branch again from scratch and decides anew. It
never forces and never merges. If no push of this claim is confirmed in five
rounds, it stops and reports one of the three states below. The message
carries the status the last push printed for the branch, if any (for example
`[rejected] (fetch first)` or `[remote rejected] (pre-receive hook declined)`),
and the push's output, stdout and stderr apart. It does not name a cause beyond
that. A stop after five rounds is not a promise that nothing was written: with
`OUTCOME_UNKNOWN` the row may already be on the branch, or land later.

**After a push, `claim` says only what it can see.** Before its first push
nothing can have reached the remote, and a refusal says "Nothing was claimed".
Once it has pushed, a claim that does not succeed ends in one of three states:

| State | Exit | When |
|---|---|---|
| `ESTABLISHED` | 0 | the branch carries this number for this file and no other. Which push wrote the row, this run's or another run's, is not said |
| `NOT_ESTABLISHED` | 1 | the branch can be read and does not carry it, and every push of this claim ended with `[rejected]` or `[remote rejected]` for the branch |
| `OUTCOME_UNKNOWN` | 3 | anything else: for some push the output did not prove a refusal, or the branch cannot be read now. Neither of the two states above is shown, and the row may be on the branch already or land later |

A push's output holds no status for the branch when the connection breaks
before git reports, and also when a `pre-push` hook of your own refuses the
push; from the outside the two look the same. Success is only ever `git push`'s
own exit status 0. Only a `!` status line with `[rejected]` or `[remote rejected]`
proves a refusal. `[remote failure]` means the remote did not report the update;
it may have happened. Other summaries and missing reports also leave the outcome
open, even if a later push is refused. Only a status line in a porcelain report block for the url `claim` pushed
to counts; what a hook writes to stderr, or prints for another url, does not.
A hook that prints such a block for the same url itself is not told apart.
On `OUTCOME_UNKNOWN` the number is neither free nor yours yet: run the same `claim` again. It reads the branch and either finds its own
row (exit 0, nothing to do), tries again, or names who holds the number. If
`claim` itself is killed, its exit status says nothing, and the same rerun
applies. The file holds the number only when a row for this number names
exactly this file and no row for it names another.

What counts as a row is the same for `next-id` and `claim`, because both read
the table through one function: the first cell is a number, the second a
backticked filename that starts with the kind, a number and a dash. Leading
zeros do not matter, so `300` and `0300` are one slot; `BUG-0300` and `FR-0300`
are two. A row written any other way, without backticks or with a path before
the name, is not seen by either of them.

`$M3C_SLOT_TABLE` names the table as a tracked file in a checkout of its
repository. The branch is the upstream of that checkout, or
`$M3C_SLOT_REF=<remote>/<branch>` when the checkout stands somewhere else.
Exactly one remote name may be a prefix of that ref.
`claim` commits in a temporary worktree and does not write to that checkout,
so the row reaches your copy of the table with your next pull.

Three honest limits:

- It is a separate verb because a slot row carries the **filename**, which does
  not exist at `next-id` time. Claiming earlier could only reserve a placeholder.
- It checks the branch at the moment it claims. A row somebody adds by hand
  afterwards, or one written in a form the reader above does not see, is not
  caught by `claim`; that is what the slot checker is for.
- It needs push rights on the table's branch and a git identity in that
  repository. Without them nothing is allocated, and it says so.

---

## Filing a bug

```bash
scripts/bugtracker.sh next-id                    # -> BUG-0213
```

Write `$M3C_MAINTENANCE_DIR/bug-reports/BUG-0213-<slug>.md` with the five fields above and
the analysis. If it stays private, you are done.

For a public bug, write the redacted body next to it as
`BUG-0213-<slug>.public.md` (**line 1 is the issue title**, the rest is the body) then:

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
  rejected, scheduled or built independently, and keep the author's own numbering out of
  this repository's id space; record it in the body instead.
- Several FRs from one proposal usually share **one** contract. Prefer a single SPEC with a
  section per area over one SPEC per FR: a contract scattered across seven documents has
  stopped being a contract.

The `/feature-request` skill runs that flow.

## Closing

```bash
scripts/bugtracker.sh close BUG-0213 --comment "Fixed in v2.11.1: see BUG-0213."
scripts/bugtracker.sh sync  BUG-0213
```

`close` sets the status and, if an issue is linked, comments and closes it. Use
`--status wontfix` or `--status duplicate` when that is the honest outcome; those close the
issue as *not planned*. `sync` exits `0` when the file and the issue tell the same story.

---

## The refusals, and why they exist

A public issue is indexed the moment it is created and cannot be un-published. Every guard
below therefore fails **closed**, it stops rather than guesses.

| `open` refuses when | Fix it by |
|---------------------|-----------|
| the item does not declare `- **Public:** yes` | deciding the plane deliberately, per item |
| there is no `.public.md` body | writing the redacted restatement |
| the body carries private-plane content | rewriting the body: **never** by working around the refusal |
| no repository is named | adding the `- **Repo:**` line |

| `close` refuses when | Fix it by |
|----------------------|-----------|
| the item has no `- **Spec:**` line and is being closed as done | answering the question, including `none, <reason>` |
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
| ID-only references (`BUG-0213`, `SPEC-0401`) | SPEC *paths*: the id alone is fine |

The patterns are not a second opinion: they live in `tools/leak-patterns.txt` and are read
by **both** gates

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

1. the recorded `- **Issue:** owner/repo#N`: after creation, this *is* the fact
2. the declared `- **Repo:** owner/repo`: before creation, reviewed in the file
3. `$M3C_BUG_REPO`: a stated override for a one-off
4. otherwise it **refuses**, naming the line to add

The file outranks the environment on purpose: an item that has declared its target must
not be redirected elsewhere by a stray variable.

> **Why there is no fallback to `git remote origin`.** `bug-reports/` holds items for
> several systems, so there is no single correct default to infer, and a default that
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

- [Manual: m3c-tools](../referenz/manual-m3c-tools.md): the capture toolkit, command by command
- [Manual: skillctl](../referenz/manual-skillctl.md): the agent-skill trust lifecycle
