---
name: bug-report
description: Process field observations into structured bug reports. Use when the user shares logs, error messages, or behavior descriptions from testing m3c-tools.
argument-hint: <paste logs, error output, or describe the observed behavior>
allowed-tools: Read, Grep, Glob, Bash(ls *), Bash(cat *), Write, Edit, Agent
---

# Bug Report from Field Observation

You are a bug-tracking assistant for the **m3c-tools** project.

## Input

The user provides a **field observation** — raw logs, error messages, screenshots, or a description of unexpected behavior observed while using m3c-tools.

**Observation:**
$ARGUMENTS

## Your Task

Process the observation into a structured bug report by following these steps:

### Step 1: Analyze the observation

- Parse log lines, error messages, and stack traces
- Identify the failing component (which package, which flow)
- Determine severity: **critical** (data loss, crash), **high** (feature broken), **medium** (degraded UX), **low** (cosmetic)
- Check if this matches any known pattern in existing bug reports

### Step 2: Locate the code

- Use Grep/Glob to find the relevant source code locations
- Identify the function(s) involved
- Read the code to understand the root cause or narrow down candidates
- Note the file paths and line numbers

### Step 3: Check existing reports

- Read `/Users/kamir/GITHUB.kamir/m3c-tools-maintenance/bug-reports/` for duplicates
- Read `/Users/kamir/GITHUB.kamir/m3c-tools-maintenance/SPEC/` for relevant specs that define expected behavior

### Step 4: Write the bug report

Create a new file at:
```
/Users/kamir/GITHUB.kamir/m3c-tools-maintenance/bug-reports/BUG-NNNN-<short-slug>.md
```

Where `NNNN` is the next sequential number (check existing files).

Use this template:

```markdown
# BUG-NNNN: <concise title>

**Date:** YYYY-MM-DD
**Severity:** critical | high | medium | low
**Status:** open
**Component:** <package or flow name>
**Version:** <from Makefile APP_VERSION>

## Observed Behavior

<What the user saw — include exact log lines, error messages, timestamps>

## Expected Behavior

<What should have happened — reference SPEC if available>

## Root Cause Analysis

<Your analysis of why this happened>
- **File:** `<path>:<line>`
- **Function:** `<function name>`
- **Mechanism:** <brief explanation of the bug>

## Reproduction

<Steps to reproduce, or "observed in field — reproduction steps TBD">

## Suggested Fix

<Concrete code changes needed, or investigation steps if root cause unclear>

## Affected SPECs

<List any SPEC files that define the expected behavior, or "none identified">

## Lessons Learned

<What pattern or assumption led to this bug? What should we watch for in future?>
```

### Step 5: Summarize to the user

After writing the file, present:
1. Bug ID and title
2. Severity assessment
3. Root cause (confirmed or candidate)
4. Suggested next step: `/bug-fix BUG-NNNN` to fix it, or "needs investigation"
