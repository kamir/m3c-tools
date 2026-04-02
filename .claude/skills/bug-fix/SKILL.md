---
name: bug-fix
description: Fix a reported bug and update SPECs with lessons learned. Use after /bug-report has created a structured bug report.
argument-hint: "BUG-NNNN (e.g. BUG-0001)"
metadata:
  version: 1.0.0
  category: development
  tags: [bug-fix, spec, m3c-tools]
---

# Bug Fix & Learning

You are a bug-fixing assistant for the **m3c-tools** project.

## Input

The user provides a **bug report ID** (e.g., `BUG-0001`) or a short slug.

**Bug reference:** $ARGUMENTS

## Your Task

Fix the bug and feed lessons back into the project's specification documents.

### Step 1: Load the bug report

- Read the bug report from `/Users/kamir/GITHUB.kamir/m3c-tools-maintenance/bug-reports/`
- If only a number is given (e.g. `0001`), search for `BUG-0001-*.md`
- Parse: severity, component, root cause analysis, suggested fix, affected SPECs

### Step 2: Understand the code

- Read the files and functions identified in the bug report's "Root Cause Analysis" section
- Read surrounding context to understand the broader flow
- Verify the root cause matches what the code actually does
- If the report's analysis is wrong or incomplete, note corrections

### Step 3: Implement the fix

- Make the minimal, targeted code change that resolves the bug
- Follow existing code patterns and conventions (see CLAUDE.md)
- Avoid side effects — do not refactor or "improve" nearby code
- If the fix touches cgo/Objective-C code, ensure thread safety (dispatch_async for UI)
- If the fix touches ER1 uploads, verify placeholder handling is preserved

### Step 4: Verify

- Run relevant tests: `go test -v -count=1 ./e2e/ -run <relevant test>`
- If no test covers this bug, note it (do NOT write a test unless asked)
- Check for compilation: `go build ./cmd/m3c-tools/`
- List any manual verification steps the user should perform

### Step 5: Update or create SPEC

Check `/Users/kamir/GITHUB.kamir/m3c-tools-maintenance/SPEC/` for an existing spec that covers the buggy behavior.

**If a relevant SPEC exists**, update it:
- Add or correct the requirement that was violated
- Reference the bug ID in a changelog/history section
- Clarify any ambiguity that led to the bug

**If no relevant SPEC exists**, create one at:
```
/Users/kamir/GITHUB.kamir/m3c-tools-maintenance/SPEC/SPEC-NNNN-<component>.md
```

Use this template:

```markdown
# SPEC-NNNN: <Component Name>

**Created:** YYYY-MM-DD
**Last updated:** YYYY-MM-DD
**Status:** active

## Purpose

<What this component does and why it exists>

## Requirements

### REQ-1: <Requirement title>

<Clear, testable requirement statement>

**Rationale:** <Why this requirement exists>

### REQ-2: ...

## Constraints

- <Technical constraints, thread safety rules, platform requirements>

## History

| Date | Change | Reference |
|------|--------|-----------|
| YYYY-MM-DD | Initial spec created from BUG-NNNN fix | BUG-NNNN |
```

### Step 6: Update the bug report

Edit the original bug report file:
- Change `**Status:** open` → `**Status:** fixed`
- Fill in or update the "Lessons Learned" section
- Add a "Fix Applied" section at the end:

```markdown
## Fix Applied

**Date:** YYYY-MM-DD
**Files changed:**
- `<path>:<line>` — <what changed>

**SPEC updated:** SPEC-NNNN-<component>.md (or "new SPEC created")

**Verification:**
- [ ] Compiles: `go build ./cmd/m3c-tools/`
- [ ] Tests pass: `<test command>`
- [ ] Manual check: <description>
```

### Step 7: Summarize to the user

Present:
1. What was fixed (1-2 sentences)
2. Files changed (with paths)
3. SPEC created or updated
4. Verification status (what passed, what needs manual check)
5. Any concerns or follow-up items
