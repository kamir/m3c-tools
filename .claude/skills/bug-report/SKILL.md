---
name: bug-report
description: Turn a field observation into a structured bug report: a private analysis file in the maintenance repo, and (opt-in, redacted) a public GitHub issue linked to it. Use when the user shares logs, error messages, or behavior descriptions from testing.
argument-hint: "<paste logs, error output, or describe the observed behavior>"
metadata:
  version: 2.0.0
  category: development
  tags: [bug-report, triage, dual-plane, m3c-tools]
---

# Bug Report from Field Observation

You are a bug-tracking assistant for the **m3c-tools** project.

## Input

The user provides a **field observation**: raw logs, error messages, screenshots,
or a description of unexpected behavior.

**Observation:**
$ARGUMENTS

## The two planes

A bug lives in up to two places, and `scripts/bugtracker.sh` keeps them in step:

| Plane | Where | Holds |
|-------|-------|-------|
| **Analysis** (private) | `${M3C_MAINTENANCE_DIR}/bug-reports/BUG-NNNN-<slug>.md` | Everything: root cause, `file:line`, customer context, SPEC references. The source of truth. |
| **Issue** (public) | a GitHub issue in the repo the report's `Repo:` line names | A **redacted restatement**: observed, expected, reproduction, version. Refers to the analysis **ID-only** (`BUG-0213`). |

The issue is **never a copy** of the analysis. `bug-reports/` also holds bugs for
systems this repository does not ship; those stay private. Publishing is per-bug,
declared in the file, and **cannot be undone**. A GitHub issue on a public repo
is indexed the moment it is created.

> Set `M3C_MAINTENANCE_DIR` before running this skill. If it is unset, say so and
> stop: do not guess a path, and never write a private path into a public file.

## Your Task

### Step 1: Analyze the observation

- Parse log lines, error messages, and stack traces.
- Identify the failing component (which package, which flow).
- Determine severity: **critical** (data loss, crash), **high** (feature broken),
  **medium** (degraded UX), **low** (cosmetic).

### Step 2: Locate the code

- Use Grep/Glob to find the relevant source locations; read the code to confirm
  or narrow the root cause. Note file paths and line numbers.

### Step 3: Check for duplicates

- Search `${M3C_MAINTENANCE_DIR}/bug-reports/` for an existing report.
- Search the issue tracker too: `gh issue list --search "<keywords>" --state all`.
- Read `${M3C_MAINTENANCE_DIR}/SPEC/` for the spec that defines expected behavior.

### Step 4: Write the analysis file

Get the next id deterministically: do not count files yourself:

```bash
./scripts/bugtracker.sh next-id      # -> BUG-0213
```

Write `${M3C_MAINTENANCE_DIR}/bug-reports/BUG-NNNN-<short-slug>.md`:

```markdown
# BUG-NNNN: <concise title>

- **Date:** YYYY-MM-DD
- **Severity:** critical | high | medium | low
- **Status:** open
- **Component:** <package or flow>
- **Version:** <from Makefile APP_VERSION>
- **Public:** yes | no
- **Repo:** <owner/repo the issue belongs in>

## Observed Behavior

<What the user saw: exact log lines, error messages, timestamps>

## Expected Behavior

<What should have happened, reference the SPEC by id if there is one>

## Root Cause Analysis

- **File:** `<path>:<line>`
- **Function:** `<name>`
- **Mechanism:** <why this happens>

## Reproduction

<Steps, or "observed in field: reproduction TBD">

## Suggested Fix

<Concrete change, or the investigation step if the cause is not yet confirmed>

## Affected SPECs

<ID-only references, or "none identified">

## Lessons Learned

<What assumption led to this? What should we watch for?>
```

`Status`, `Public`, `Repo` and `Issue` are the lines the script owns: keep their
exact spelling so `status`, `open`, `close` and `sync` can parse them.

`Repo` names the repository the issue belongs in. It is **not** inferred from the
working directory: `bug-reports/` holds items for several systems, and guessing
from wherever you happen to stand is how an issue lands in the wrong repository.

### Step 5: Decide the plane

Set `- **Public:** yes` **only** when all of these hold:

- the bug is in the **shipped artifact** of this repository (m3c-tools / skillctl),
- it is **not** a security issue (those go through the private plane and a
  security advisory, never a public issue),
- it carries **no** customer-specific or tenant-specific detail,
- a stranger reading it learns nothing about internal infrastructure.

Otherwise set `- **Public:** no`, tell the user why, and stop after Step 4. That
is a complete outcome, not a failure.

### Step 6: Write the redacted body

For a public bug, write the issue body to a sibling file:

```
${M3C_MAINTENANCE_DIR}/bug-reports/BUG-NNNN-<slug>.public.md
```

Line 1 is the issue title (`# <title>`); the rest is the body. Restate the bug
for someone with no access to the private plane:

- **keep:** observed behavior, expected behavior, reproduction, affected version,
  the user-visible command and its output, the ID-only reference `BUG-NNNN`
- **drop:** paths into the maintenance repo, internal endpoints, ER1 context-ids,
  `X-API-KEY`, internal API paths, customer names, SPEC *paths* (ids are fine),
  and any root-cause detail that is really internal design discussion

Write it as a restatement, not a summary of the analysis. Someone should be able
to confirm the bug from it without ever seeing the private file.

### Step 7: Open the issue

```bash
./scripts/bugtracker.sh open BUG-NNNN
```

The script refuses unless `Public: yes` is declared, the `.public.md` body
exists, and the body passes the same five leak patterns `tools/boundary-gate.sh`
enforces in CI (SPEC-0358). If it refuses, **fix the body: never work around
the refusal.** On success it writes `- **Issue:** owner/repo#NN` back into the
analysis file.

### Step 8: Summarize to the user

1. Bug id and title
2. Severity and component
3. Root cause: confirmed, or the leading candidate
4. Which planes exist now (private only, or private + issue URL)
5. Next step: `/bug-fix BUG-NNNN`, or the investigation still needed
