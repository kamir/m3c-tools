---
name: bug-fix
description: Fix a reported bug, feed the lesson back into the SPECs, and close both planes: the private analysis file and its public GitHub issue. Use after /bug-report has created a structured bug report.
argument-hint: "BUG-NNNN (e.g. BUG-0213)"
metadata:
  version: 2.0.0
  category: development
  tags: [bug-fix, spec, dual-plane, m3c-tools]
---

# Bug Fix & Learning

You are a bug-fixing assistant for the **m3c-tools** project.

## Input

**Bug reference:** $ARGUMENTS

A bug id (`BUG-0213`), a bare number (`213`), or a filename: `scripts/bugtracker.sh`
normalises all three.

> Set `M3C_MAINTENANCE_DIR` before running this skill. If it is unset, say so and
> stop.

## Your Task

Fix the bug, feed the lesson into the specs, and leave **both planes** (the
private analysis file and, if one exists, its public issue) in agreement.

### Step 1: Load the report

```bash
./scripts/bugtracker.sh path   BUG-NNNN    # the analysis file
./scripts/bugtracker.sh status BUG-NNNN    # open | in-progress | fixed | wontfix | duplicate
./scripts/bugtracker.sh issue  BUG-NNNN    # owner/repo#NN, or empty if private-only
```

Read the file. Parse severity, component, root cause, suggested fix, affected SPECs.
If the bug is already `fixed`, say so and stop unless the user wants it reopened.

Mark that you have started:

```bash
./scripts/bugtracker.sh status BUG-NNNN in-progress
```

### Step 2: Understand the code

- Read the files and functions named in "Root Cause Analysis", plus enough
  surrounding context to see the flow.
- Verify the analysis against what the code actually does. **If the report is
  wrong or incomplete, correct it**. A report that misdiagnoses is worse than
  none, and the correction is the most valuable thing you will write today.

### Step 3: Implement the fix

- The minimal, targeted change that resolves the bug.
- Follow the surrounding conventions (see CLAUDE.md). Do not refactor nearby code.
- cgo/Objective-C: keep UI work on `dispatch_async`.
- ER1 uploads: preserve the placeholder audio/image handling.

### Step 4: Verify

- Run the relevant tests: `go test -v -count=1 ./e2e/ -run <test>` (or the
  package's own tests).
- `go build ./cmd/m3c-tools/`, and `go vet ./...` if the change is non-trivial.
- If a CLI flag was added, removed or renamed, the manual must move with it:
  `go run ./cmd/docaudit -cli all` (the release gate; `-scaffold` drafts entries).
- If no test covers this bug, **say so plainly**. Do not write one unless asked.
- Report failures with their output. Never describe an unrun check as passing.

### Step 5: Update or create the SPEC

Check `${M3C_MAINTENANCE_DIR}/SPEC/` for a spec covering the buggy behavior.

**If one exists**, update it: add or correct the violated requirement, reference
the bug id in its history table, and remove the ambiguity that allowed the bug.

**If none exists**, create `${M3C_MAINTENANCE_DIR}/SPEC/SPEC-NNNN-<component>.md`:

```markdown
# SPEC-NNNN: <Component Name>

**Created:** YYYY-MM-DD
**Status:** active

## Purpose

<What this component does and why it exists>

## Requirements

### REQ-1: <title>

<Clear, testable statement>

**Rationale:** <why>

## Constraints

- <thread safety, platform, protocol constraints>

## History

| Date | Change | Reference |
|------|--------|-----------|
| YYYY-MM-DD | Initial spec created from the BUG-NNNN fix | BUG-NNNN |
```

### Step 6: Record the fix in the analysis file

Append to `BUG-NNNN-<slug>.md`:

```markdown
## Fix Applied

**Date:** YYYY-MM-DD
**Files changed:**
- `<path>:<line>`: <what changed>

**SPEC updated:** SPEC-NNNN (or "new SPEC created")

**Verification:**
- Builds: `go build ./cmd/m3c-tools/`
- Tests: `<command>`: <result>
- Manual: <what the user should check by hand, if anything>
```

Also fill in "Lessons Learned": the assumption that allowed the bug, not a
restatement of the fix.

### Step 7: Close both planes

```bash
./scripts/bugtracker.sh close BUG-NNNN --comment "<public-safe one-liner>"
```

This sets `Status: fixed` in the analysis file and, if an issue is linked,
comments and closes it. Use `--status wontfix` or `--status duplicate` when that
is the honest outcome; those close the issue as *not planned*.

`close` **refuses** unless the report carries a `- **Spec:**` line: solving a bug
means serving the contract it belongs to. `none: <reason>` is a valid answer
when a bug genuinely changes no contract; a missing line is not, because that is
how Step 5 gets skipped rather than decided.

The comment is **public-plane text**: the script runs the SPEC-0358 leak check on
it and refuses rather than post. Write it for a stranger: what changed and in
which version, referring to the analysis ID-only.

If the bug is private-only, the command still updates the file and simply reports
that there is no issue to close.

### Step 8: Confirm they agree

```bash
./scripts/bugtracker.sh sync BUG-NNNN
```

Exit 0 means the file and the issue tell the same story.

### Step 9: Summarize to the user

1. What was fixed (1–2 sentences)
2. Files changed, with paths
3. SPEC created or updated
4. Verification: what passed, what failed, what still needs a human
5. Both planes' final state (status + issue URL, or "private-only")
6. Any follow-up you did **not** do, and why
