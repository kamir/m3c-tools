---
name: feature-request
description: Turn a proposal or design critique into tracked feature requests: an FR file per request in the maintenance repo, the SPEC section each one answers to, and a public GitHub issue linked to both. Use when someone proposes a capability, challenges an architecture, or when an audio/meeting note contains several distinct asks.
argument-hint: "<paste the proposal, critique, or transcript>"
metadata:
  version: 1.0.0
  category: development
  tags: [feature-request, spec, dual-plane, m3c-tools]
---

# Feature Request from a Proposal

## Input

**Proposal:**
$ARGUMENTS

## The three artifacts

| Artifact | Where | Answers |
|----------|-------|---------|
| **FR file** (private) | `${M3C_MAINTENANCE_DIR}/bug-reports/FR-NNNN-<slug>.md` | *What is being asked, by whom, and why.* Full reasoning, trade-offs, the arguments against. |
| **SPEC** (private) | `${M3C_MAINTENANCE_DIR}/SPEC/SPEC-NNNN-<name>.md` | *What contract the result must satisfy.* Requirements, constraints, non-goals. |
| **Issue** (public) | a GitHub issue in the repo the FR's `Repo:` line names | *What will change for a user of this tool.* Redacted; refers to the FR and SPEC **ID-only**. |

The FR is the **ask**; the SPEC is the **contract**; the issue is the **public
commitment**. Closing an issue means the contract is served: `bugtracker.sh`
enforces that mechanically by refusing to close an item whose `- **Spec:**`
line is missing.

> Set `M3C_MAINTENANCE_DIR` before running this skill. If it is unset, say so
> and stop.

## Your Task

### Step 1: Split the proposal into distinct asks

A proposal is rarely one feature request. Read for the **seams**: a separate FR
is warranted where the asks could be accepted, rejected, scheduled or built
*independently*.

Resist two failure modes:

- **Splitting too fine.** Two asks that must ship together are one FR.
- **Keeping the author's numbering.** A proposal that says "FR-1 … FR-7" is
  using its own scheme. The repository has its own; `bugtracker.sh next-id FR`
  is the only source of an id. Record the author's label in the FR body so the
  conversation stays traceable.

Present the split to the user and get agreement **before** writing files. This
is the step where a wrong reading is cheapest to correct.

### Step 2: Find the contract underneath

Several FRs from one proposal usually share **one** contract. Prefer a single
SPEC with a section per area over one SPEC per FR. Fragmenting a contract
across seven documents is how it stops being a contract.

Check `${M3C_MAINTENANCE_DIR}/SPEC/` first: an existing SPEC that already owns
this area should be **extended**, not duplicated.

Write down the **non-goals** explicitly. A proposal that expands what the tool
is responsible for is a proposal to change its boundary; if that boundary should
hold, saying so in the SPEC is the most valuable line in it.

### Step 3: Write the SPEC

```bash
ls ${M3C_MAINTENANCE_DIR}/SPEC | sed -nE 's/^SPEC-0*([0-9]+).*/\1/p' | sort -n | tail -1
```

Follow the house format: purpose, numbered requirements with rationale,
constraints, non-goals, and a history table. Each requirement must be **testable**
: "the manifest declares data requirements semantically" is a wish; "`validate`
exits non-zero when a declared requirement has no binding" is a requirement.

Mark anything not yet decided as an open question rather than inventing an
answer. A SPEC that quietly resolves a real design decision is worse than one
that names it.

### Step 4: Write the FR files

```bash
./scripts/bugtracker.sh next-id FR      # -> FR-0096  (a ceiling, not a claim)
```

Write the file, then **claim the number**, reading a ceiling allocates nothing,
and two sessions asking at the same moment get the same answer:

```bash
./scripts/bugtracker.sh claim FR-0096
```

The claim is durable only once the slot table is committed.

One file per ask, `${M3C_MAINTENANCE_DIR}/bug-reports/FR-NNNN-<slug>.md`:

```markdown
# FR-NNNN: <what is being asked, in one line>

- **Date:** YYYY-MM-DD
- **Status:** open
- **Raised by:** <who, and in what conversation>
- **Component:** <package or surface>
- **Spec:** SPEC-NNNN §N
- **Public:** yes | no
- **Repo:** <owner/repo the issue belongs in>

## The ask

<What is wanted, in the requester's terms>

## Why it matters

<The problem it solves. If the requester gave a rationale, keep theirs.>

## What it changes

<Concretely: manifest fields, CLI surface, verification behaviour>

## Arguments against / open questions

<The strongest case for NOT doing it, and what is still undecided. An FR
without this section is advocacy, not analysis.>

## Acceptance

<What must be true to close this: pointing at the SPEC requirements it serves>
```

### Step 5: Decide the plane

Set `- **Public:** yes` only when all hold:

- the request concerns the **shipped artifact** of this repository,
- it is not a security-sensitive design detail,
- it carries no customer-specific or tenant-specific context,
- the requester is content to be named publicly, or the FR is restated without
  attributing them.

Otherwise `- **Public:** no`, say why, and stop after Step 4.

### Step 6: Write the redacted issue bodies

`${M3C_MAINTENANCE_DIR}/bug-reports/FR-NNNN-<slug>.public.md`: line 1 is the
title, the rest the body. Write it for a **contributor**, not for the internal
reader:

- **keep:** what the capability is, why a user wants it, what would change in
  the manifest/CLI, acceptance criteria, ID-only references (`FR-0096`, `SPEC-0401`)
- **drop:** paths into the maintenance repo, internal endpoints, ER1 context-ids,
  `X-API-KEY`, internal API paths, customer names, SPEC *paths*, and internal
  strategy or competitive reasoning

An issue is a request for work, so it must be **actionable by someone who cannot
read the SPEC**. If the body only makes sense with the private document open,
it is not finished.

### Step 7: Show, then open

Show the user every redacted body **before** creating anything. A GitHub issue on
a public repository is indexed immediately and cannot be un-published. This
confirmation is the last reversible moment.

```bash
./scripts/bugtracker.sh open FR-NNNN
```

The script refuses unless `Public: yes` is declared, the `.public.md` exists, and
the body passes the SPEC-0358 leak check. **Fix the body; never work around the
refusal.**

### Step 8: Closing one later

An FR closes as **implemented**, and only once the contract is served:

```bash
./scripts/bugtracker.sh close FR-NNNN --comment "<public-safe one-liner>"
./scripts/bugtracker.sh sync FR-NNNN
```

`close` refuses when the `- **Spec:**` line is missing. Solving an issue means
serving the SPEC it belongs to. Update the SPEC's history table in the same
change, and record in the FR what was actually built versus what was asked;
where they differ, that difference is the most useful thing in the file.

### Step 9: Summarize

1. The split you made, and why those seams
2. SPEC created or extended, with its requirement ids
3. Each FR: id, one-line ask, plane
4. Issue URLs, or what is still awaiting confirmation
5. Open questions the SPEC deliberately left unresolved
